"""Nostr wrapping of agent actions."""

import pytest

from veritas.crypto import OracleKey
from veritas.nostr import NostrEvent

from vrt1_agents.action import make_action, sign_action
from vrt1_agents.nostr import (
    KIND_AGENT_ACTION,
    build_action_event,
    decode_action_event,
    extract_parent_id,
)


def test_event_roundtrip_preserves_signed_action():
    k = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="https://x", outcome={"v": 1},
    )
    signed = sign_action(a, k)
    evt = build_action_event(signed, k)
    assert evt.verify()
    assert evt.kind == KIND_AGENT_ACTION
    assert evt.pubkey == k.xonly_pubkey_hex
    decoded = decode_action_event(evt)
    assert decoded.id == signed.id
    assert decoded.verify()


def test_event_tags_include_d_t_e_no_p():
    k = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="vouch", target="x", parent_action="bb" * 32,
    )
    signed = sign_action(a, k)
    evt = build_action_event(signed, k)
    tag_keys = {t[0] for t in evt.tags}
    assert {"d", "t", "e"}.issubset(tag_keys)
    assert ["t", "vouch"] in evt.tags
    assert ["e", "bb" * 32] in evt.tags
    # No self-pointing p-tag (NIP-01 reserves p for OTHER pubkeys).
    assert "p" not in tag_keys


def test_decode_rejects_outer_event_signed_by_unrelated_key():
    """High-severity round-2 finding: decode_action_event must verify
    the OUTER Nostr event sig so an attacker can't re-wrap a valid
    SignedAction under a different key and have it accepted."""
    alice = OracleKey.generate()
    eve = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="review", target="https://x",
    )
    signed_by_alice = sign_action(a, alice)
    # Eve builds a Nostr event around Alice's signed action but signs
    # the OUTER event with her own key. The inner SignedAction sig
    # still verifies (Alice signed it), but the Nostr layer claim
    # "Eve published this" is a lie.
    import base64
    forged_evt = NostrEvent(
        pubkey=eve.xonly_pubkey_hex,
        created_at=signed_by_alice.action.ts,
        kind=KIND_AGENT_ACTION,
        tags=[["d", signed_by_alice.id], ["t", "review"]],
    )
    forged_evt.content = base64.b64encode(
        signed_by_alice.to_json().encode("utf-8"),
    ).decode("ascii")
    forged_evt.sign(eve)

    with pytest.raises(ValueError, match="match outer Nostr event"):
        decode_action_event(forged_evt)


def test_decode_verify_outer_false_bypasses_check():
    """The verify_outer=False escape hatch lets callers skip the outer
    check when they've verified it separately or genuinely don't care."""
    alice = OracleKey.generate()
    eve = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="review", target="x",
    )
    signed_by_alice = sign_action(a, alice)
    import base64
    forged_evt = NostrEvent(
        pubkey=eve.xonly_pubkey_hex,
        created_at=signed_by_alice.action.ts,
        kind=KIND_AGENT_ACTION,
        tags=[["d", signed_by_alice.id], ["t", "review"]],
    )
    forged_evt.content = base64.b64encode(
        signed_by_alice.to_json().encode("utf-8"),
    ).decode("ascii")
    forged_evt.sign(eve)

    sa = decode_action_event(forged_evt, verify_outer=False)
    # Inner sig still valid (Alice signed the inner action), caller
    # opts into trusting that without the transport-layer check.
    assert sa.verify()


def test_event_no_e_tag_when_no_parent():
    k = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x",
    )
    signed = sign_action(a, k)
    evt = build_action_event(signed, k)
    assert not any(t[0] == "e" for t in evt.tags)


def test_build_event_rejects_mismatched_key():
    k = OracleKey.generate()
    other = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x",
    )
    signed = sign_action(a, k)
    with pytest.raises(ValueError, match="does not match"):
        build_action_event(signed, other)


def test_decode_rejects_wrong_kind():
    k = OracleKey.generate()
    evt = NostrEvent(
        pubkey=k.xonly_pubkey_hex, created_at=1700000000,
        kind=1, tags=[], content="ZZZZ",
    )
    with pytest.raises(ValueError, match="expected kind"):
        decode_action_event(evt)


def test_extract_parent_id():
    k = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="vouch", target="x", parent_action="cc" * 32,
    )
    signed = sign_action(a, k)
    evt = build_action_event(signed, k)
    assert extract_parent_id(evt) == "cc" * 32

    a_no_parent = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x",
    )
    evt_no = build_action_event(sign_action(a_no_parent, k), k)
    assert extract_parent_id(evt_no) is None
