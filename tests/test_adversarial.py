"""Adversarial tests for vrt1-agents.

Each test names an attack vrt1-agents MUST refuse, miscount, or
silently mis-aggregate. Regression dams against any future change
that weakens action signing, Nostr-event binding, or reputation
aggregation invariants.

Coverage:
  - Forged actions (tampered fields, wrong-key signing, replayed sigs)
  - Forged Nostr wrappers (attacker re-wraps valid SignedAction)
  - Reputation cycles + Sybil simulation (documented limits)
  - Replay of identical actions (deterministic id collapse)
  - Type-confusion attacks (params/outcome non-dict)
  - Parent-action substitution (vouching for a different parent)
  - Verify CLI exit codes for script gating
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from veritas.crypto import OracleKey
from veritas.nostr import NostrEvent

from vrt1_agents.action import (
    AgentAction,
    SignedAction,
    action_id,
    make_action,
    sign_action,
)
from vrt1_agents.nostr import (
    KIND_AGENT_ACTION,
    build_action_event,
    decode_action_event,
)
from vrt1_agents.reputation import (
    build_vouch_graph,
    history_for,
    summarize,
)


# ---------- helpers ------------------------------------------------


def _review(key: OracleKey, target: str = "https://x", ts: int = 1) -> SignedAction:
    return sign_action(
        make_action(
            agent_pubkey_hex=key.xonly_pubkey_hex,
            action_type="review", target=target, ts=ts,
            outcome={"verdict": "ok"},
        ),
        key,
    )


def _vouch(key: OracleKey, parent: SignedAction, ts: int = 2) -> SignedAction:
    return sign_action(
        make_action(
            agent_pubkey_hex=key.xonly_pubkey_hex,
            action_type="vouch", target=parent.id,
            parent_action=parent.id, ts=ts,
        ),
        key,
    )


@pytest.fixture
def two_agents_review_and_vouch():
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    review = _review(alice, target="https://news.example/article")
    vouch = _vouch(bob, review)
    return {"alice": alice, "bob": bob, "review": review, "vouch": vouch}


# ---------- baseline -----------------------------------------------


def test_baseline_honest_flow(two_agents_review_and_vouch):
    h = two_agents_review_and_vouch
    assert h["review"].verify()
    assert h["vouch"].verify()
    g = build_vouch_graph([h["review"], h["vouch"]])
    assert g.in_degree(h["alice"].xonly_pubkey_hex) == 1
    assert g.out_degree(h["bob"].xonly_pubkey_hex) == 1


# ---------- action signing attacks ---------------------------------


def test_rejects_tampered_action_output_post_sign(two_agents_review_and_vouch):
    forged = copy.deepcopy(two_agents_review_and_vouch["review"])
    forged.action.outcome = {"verdict": "tampered"}
    assert forged.verify() is False


def test_rejects_tampered_action_target_post_sign(two_agents_review_and_vouch):
    forged = copy.deepcopy(two_agents_review_and_vouch["review"])
    forged.action.target = "https://attacker.example/different"
    assert forged.verify() is False


def test_rejects_swapped_agent_field_post_sign(two_agents_review_and_vouch):
    h = two_agents_review_and_vouch
    forged = copy.deepcopy(h["review"])
    forged.action.agent = h["bob"].xonly_pubkey_hex
    assert forged.verify() is False


def test_sign_refuses_wrong_agent_key():
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="review", target="x",
    )
    with pytest.raises(ValueError, match="does not match"):
        sign_action(a, bob)


def test_from_json_with_all_zero_sig_fails_verify():
    """Attacker hand-crafts a JSON file claiming an action they didn't sign."""
    alice = OracleKey.generate()
    body = json.dumps({
        "action": {
            "agent": alice.xonly_pubkey_hex,
            "action_type": "review", "target": "https://x",
            "params": {}, "outcome": {}, "ts": 1, "v": 1,
        },
        "sig": "00" * 64,
    })
    sa = SignedAction.from_json(body)
    assert sa.verify() is False


# ---------- Nostr wrapper attacks ----------------------------------


def test_decode_rejects_outer_event_signed_by_eve(two_agents_review_and_vouch):
    """Round-2 fix in action: an attacker re-wraps Alice's valid
    SignedAction under their own Nostr key. Inner sig still valid,
    but the outer transport-layer claim 'Eve published this' is a
    forgery. decode_action_event must refuse."""
    h = two_agents_review_and_vouch
    eve = OracleKey.generate()
    forged_evt = NostrEvent(
        pubkey=eve.xonly_pubkey_hex,
        created_at=h["review"].action.ts,
        kind=KIND_AGENT_ACTION,
        tags=[["d", h["review"].id], ["t", "review"]],
    )
    forged_evt.content = base64.b64encode(
        h["review"].to_json().encode("utf-8")
    ).decode("ascii")
    forged_evt.sign(eve)
    with pytest.raises(ValueError, match="outer Nostr event"):
        decode_action_event(forged_evt)


def test_decode_rejects_event_with_corrupted_inner_sig(two_agents_review_and_vouch):
    """Round-3 fix: decode_action_event verifies BOTH the outer Nostr
    sig AND the inner SignedAction sig. An event with a valid outer
    wrapper but a corrupted inner sig (torn write, attacker who can
    sign Nostr events but not the inner action) used to silently
    return the SignedAction; now it raises."""
    h = two_agents_review_and_vouch
    # Build a fresh event where Alice signs everything legitimately,
    # then tamper the inner action's outcome (which invalidates the
    # inner sig but leaves the OUTER event valid because we re-sign).
    real_evt = build_action_event(h["review"], h["alice"])
    # Decode + mutate the inner JSON + re-base64 + re-sign the OUTER.
    inner = json.loads(base64.b64decode(real_evt.content))
    inner["action"]["outcome"] = {"verdict": "tampered"}
    new_content = base64.b64encode(json.dumps(inner).encode()).decode()
    forged_evt = NostrEvent(
        pubkey=h["alice"].xonly_pubkey_hex,
        created_at=real_evt.created_at,
        kind=KIND_AGENT_ACTION,
        tags=real_evt.tags,
    )
    forged_evt.content = new_content
    forged_evt.sign(h["alice"])   # Alice re-signs the OUTER

    # Outer verifies (Alice signed it), inner doesn't (sig is for
    # original outcome). decode must catch this.
    assert forged_evt.verify()  # outer OK
    with pytest.raises(ValueError, match="inner SignedAction"):
        decode_action_event(forged_evt)


def test_from_json_normalizes_falsy_parent_action_values():
    """Round-3 fix: from_json normalizes ALL falsy parent_action values
    (None, '', 0, false, []) to None before construction. Previously
    only literal empty string hit __post_init__; values like 0 or
    null survived into canonical_bytes and produced different action_ids
    for semantically-equivalent inputs."""
    k = OracleKey.generate()
    # Build the base no-parent payload manually so we control the JSON shape.
    base_action = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x", ts=1700000000,
        parent_action=None,
    )
    canonical_signed = sign_action(base_action, k)
    canonical_id = canonical_signed.id

    for weird_parent in [None, "", 0, False, []]:
        body = json.loads(canonical_signed.to_json())
        body["action"]["parent_action"] = weird_parent
        sa = SignedAction.from_json(json.dumps(body))
        assert sa.id == canonical_id, (
            f"falsy parent_action={weird_parent!r} should produce the "
            f"canonical no-parent action_id"
        )


def test_from_json_accepts_null_params_and_outcome():
    """Round-3 fix: from_json coerces null params/outcome to {} so
    a corpus file with explicit `"params": null` still loads. Without
    this, round-2's strict type check in __post_init__ rejects None
    and breaks backward compat."""
    k = OracleKey.generate()
    payload = json.dumps({
        "action": {
            "agent": k.xonly_pubkey_hex,
            "action_type": "review", "target": "x",
            "params": None, "outcome": None,
            "ts": 1, "v": 1,
        },
        "sig": "00" * 64,
    })
    sa = SignedAction.from_json(payload)
    assert sa.action.params == {}
    assert sa.action.outcome == {}


def test_decode_rejects_wrong_kind():
    k = OracleKey.generate()
    evt = NostrEvent(
        pubkey=k.xonly_pubkey_hex, created_at=1, kind=1, tags=[], content="",
    )
    with pytest.raises(ValueError, match="expected kind"):
        decode_action_event(evt)


def test_decode_rejects_tampered_event_content(two_agents_review_and_vouch):
    """Attacker mutates the base64 content after the event was signed —
    Nostr event.verify() should catch it (content is part of the
    canonical id)."""
    h = two_agents_review_and_vouch
    real_evt = build_action_event(h["review"], h["alice"])
    forged = copy.deepcopy(real_evt)
    forged.content = base64.b64encode(b'{"forged": true}').decode("ascii")
    # Event id no longer matches because content changed.
    assert forged.verify() is False
    with pytest.raises(ValueError, match="outer Nostr event"):
        decode_action_event(forged)


# ---------- reputation aggregation attacks --------------------------


def test_summarize_excludes_dangling_vouch(two_agents_review_and_vouch):
    """A vouch whose parent isn't in the corpus must not inflate the
    target agent's reputation."""
    h = two_agents_review_and_vouch
    # Bob vouches for a non-existent action.
    dangling = sign_action(
        make_action(
            agent_pubkey_hex=h["bob"].xonly_pubkey_hex,
            action_type="vouch", target="dd" * 32,
            parent_action="dd" * 32, ts=10,
        ),
        h["bob"],
    )
    summ = summarize(h["alice"].xonly_pubkey_hex, [h["review"], dangling])
    assert summ.vouches_received_from == set()


def test_summarize_excludes_vouch_over_invalid_parent(two_agents_review_and_vouch):
    """Bob vouches for Alice's review, then someone tampers Alice's
    review post-sign. The vouch must not count (the parent doesn't
    verify, so the vouch is meaningless)."""
    h = two_agents_review_and_vouch
    forged_review = copy.deepcopy(h["review"])
    forged_review.action.outcome = {"verdict": "tampered"}
    assert forged_review.verify() is False
    summ = summarize(h["alice"].xonly_pubkey_hex, [forged_review, h["vouch"]])
    assert summ.vouches_received_from == set()


def test_self_vouch_excluded_from_in_degree(two_agents_review_and_vouch):
    """Alice cannot vouch for her own action to inflate her reputation."""
    h = two_agents_review_and_vouch
    self_vouch = sign_action(
        make_action(
            agent_pubkey_hex=h["alice"].xonly_pubkey_hex,
            action_type="vouch", target=h["review"].id,
            parent_action=h["review"].id, ts=5,
        ),
        h["alice"],
    )
    g = build_vouch_graph([h["review"], self_vouch])
    assert g.in_degree(h["alice"].xonly_pubkey_hex) == 0


def test_vouch_cycle_still_inflates_in_degree_documented():
    """DOCUMENTED LIMITATION: vouch cycles (Alice→Bob→Alice) inflate
    both agents' in-degrees. The round-2 fix updated the docstring/
    comment to clarify this — cycle detection is the consumer's job.
    Test confirms the behavior so it can't be silently changed."""
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    alice_review = _review(alice, ts=1)
    bob_review = _review(bob, target="https://other", ts=2)
    # Cycle: Alice vouches for Bob, Bob vouches for Alice.
    alice_vouches_bob = sign_action(make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="vouch", target=bob_review.id,
        parent_action=bob_review.id, ts=3,
    ), alice)
    bob_vouches_alice = sign_action(make_action(
        agent_pubkey_hex=bob.xonly_pubkey_hex,
        action_type="vouch", target=alice_review.id,
        parent_action=alice_review.id, ts=4,
    ), bob)
    g = build_vouch_graph([alice_review, bob_review,
                           alice_vouches_bob, bob_vouches_alice])
    # Both agents get inflated in-degree from each other — the library
    # ships this behavior on purpose; SCC removal is the consumer's job.
    assert g.in_degree(alice.xonly_pubkey_hex) == 1
    assert g.in_degree(bob.xonly_pubkey_hex) == 1


def test_sybil_simulation_inflates_in_degree_documented():
    """DOCUMENTED LIMITATION: an operator with 1000 keys can mint
    1000 vouches for one target agent. The library doesn't try to
    detect this — that's the consumer's external trust layer."""
    target = OracleKey.generate()
    target_review = _review(target, ts=1)
    corpus = [target_review]
    for i in range(50):  # simulate 50 sybil keys (1000 would slow tests)
        sybil = OracleKey.generate()
        sybil_vouch = sign_action(make_action(
            agent_pubkey_hex=sybil.xonly_pubkey_hex,
            action_type="vouch", target=target_review.id,
            parent_action=target_review.id, ts=2 + i,
        ), sybil)
        corpus.append(sybil_vouch)
    g = build_vouch_graph(corpus)
    # All 50 sybils count individually — the library doesn't deduplicate
    # by IP, cost, or external identity. This is the test that documents
    # the limitation; consumers MUST layer trust signals on top.
    assert g.in_degree(target.xonly_pubkey_hex) == 50


def test_repeat_vouch_from_same_agent_counts_once():
    """Same Bob vouching twice for Alice's review only inflates in_degree
    by 1, not 2 — vouches are deduped by (voucher, target) pair."""
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    review = _review(alice, ts=1)
    v1 = _vouch(bob, review, ts=2)
    v2 = _vouch(bob, review, ts=3)
    g = build_vouch_graph([review, v1, v2])
    assert g.in_degree(alice.xonly_pubkey_hex) == 1


def test_history_for_correctly_flags_invalid_entries(two_agents_review_and_vouch):
    h = two_agents_review_and_vouch
    forged = copy.deepcopy(h["review"])
    forged.action.target = "https://attacker.example"
    hist = history_for(h["alice"].xonly_pubkey_hex, [h["review"], forged])
    # Both appear in history; one valid, one not.
    assert hist.count == 2
    assert hist.valid_count == 1


# ---------- replay + identity attacks ------------------------------


def test_identical_actions_have_identical_ids():
    """Bob signs the same vouch content twice — same action_id, deterministic.
    Replay of an identical action is idempotent at the protocol level."""
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    review = _review(alice, ts=1)
    v1 = _vouch(bob, review, ts=2)
    v2 = _vouch(bob, review, ts=2)  # identical ts → identical content
    assert v1.id == v2.id


def test_attacker_signed_action_doesnt_claim_other_agent():
    """Eve signs an action; she can sign anything she wants, but the
    'agent' field is HER pubkey because sign_action enforces it."""
    eve = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=eve.xonly_pubkey_hex,
        action_type="review", target="https://victim.example",
    )
    signed = sign_action(a, eve)
    # The signature is valid for Eve's key — but the action attributes
    # claims to Eve, not anyone else.
    assert signed.verify()
    assert signed.action.agent == eve.xonly_pubkey_hex


# ---------- type-confusion attacks ---------------------------------


def test_from_json_rejects_params_as_string():
    """An attacker publishes an action whose params is a string (not dict).
    Round-2 fix added type validation at construction + from_json."""
    k = OracleKey.generate()
    payload = json.dumps({
        "action": {
            "agent": k.xonly_pubkey_hex,
            "action_type": "review", "target": "x",
            "params": "not-a-dict",
            "outcome": {}, "ts": 1, "v": 1,
        },
        "sig": "00" * 64,
    })
    with pytest.raises(ValueError, match="params must be a dict"):
        SignedAction.from_json(payload)


def test_from_json_rejects_outcome_as_list():
    k = OracleKey.generate()
    payload = json.dumps({
        "action": {
            "agent": k.xonly_pubkey_hex,
            "action_type": "review", "target": "x",
            "params": {}, "outcome": ["a", "b"],
            "ts": 1, "v": 1,
        },
        "sig": "00" * 64,
    })
    with pytest.raises(ValueError, match="outcome must be a dict"):
        SignedAction.from_json(payload)


def test_empty_string_parent_normalized_for_deterministic_id():
    """Round-2 fix: parent_action='' is normalized to None so two
    semantically-equivalent actions don't get different ids."""
    k = OracleKey.generate()
    a_empty = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x", parent_action="",
    )
    a_none = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x", parent_action=None,
    )
    assert action_id(a_empty) == action_id(a_none)


# ---------- parent substitution attack -----------------------------


def test_vouch_referencing_different_parent_doesnt_apply_to_original():
    """Bob signs a vouch with parent_action=X. An attacker can't take
    Bob's vouch and re-apply it to a different action Y — the parent
    is part of the signed content, so changing it breaks verify."""
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    review_x = _review(alice, target="https://x", ts=1)
    review_y = _review(alice, target="https://y", ts=2)
    vouch_x = _vouch(bob, review_x, ts=3)

    # Attacker tries to make vouch_x apply to review_y.
    forged = copy.deepcopy(vouch_x)
    forged.action.parent_action = review_y.id
    forged.action.target = review_y.id
    assert forged.verify() is False


# ---------- aggregation stability ----------------------------------


def test_aggregation_is_deterministic(two_agents_review_and_vouch):
    h = two_agents_review_and_vouch
    corpus = [h["review"], h["vouch"]]
    g1 = build_vouch_graph(corpus)
    g2 = build_vouch_graph(corpus)
    assert g1.edges == g2.edges
    assert g1.in_edges == g2.in_edges
