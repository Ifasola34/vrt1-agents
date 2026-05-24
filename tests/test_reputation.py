"""Reputation aggregation correctness."""

import copy

import pytest

from veritas.crypto import OracleKey

from vrt1_agents.action import make_action, sign_action
from vrt1_agents.reputation import (
    build_vouch_graph,
    history_for,
    summarize,
)


@pytest.fixture
def two_agents_and_a_review():
    """Agent A publishes a review; agent B vouches for it.

    Returns (alice_key, bob_key, [signed_actions]).
    """
    alice = OracleKey.generate()
    bob = OracleKey.generate()

    review = make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="review", target="https://news.example/article-42",
        outcome={"verdict": "trustworthy"}, ts=1700000000,
    )
    signed_review = sign_action(review, alice)

    vouch = make_action(
        agent_pubkey_hex=bob.xonly_pubkey_hex,
        action_type="vouch", target=signed_review.id,
        parent_action=signed_review.id, ts=1700000050,
    )
    signed_vouch = sign_action(vouch, bob)

    return alice, bob, [signed_review, signed_vouch]


def test_history_returns_actions_sorted_by_ts(two_agents_and_a_review):
    alice, _, actions = two_agents_and_a_review
    hist = history_for(alice.xonly_pubkey_hex, actions)
    assert hist.count == 1
    assert hist.valid_count == 1
    assert hist.entries[0].id == actions[0].id


def test_history_excludes_other_agents(two_agents_and_a_review):
    alice, bob, actions = two_agents_and_a_review
    bob_hist = history_for(bob.xonly_pubkey_hex, actions)
    assert bob_hist.count == 1
    assert bob_hist.entries[0].signed.action.action_type == "vouch"


def test_history_flags_invalid_actions(two_agents_and_a_review):
    alice, _, actions = two_agents_and_a_review
    forged = copy.deepcopy(actions[0])
    forged.action.outcome = {"verdict": "tampered"}
    hist = history_for(alice.xonly_pubkey_hex, actions + [forged])
    # Two entries, one valid + one invalid.
    assert hist.count == 2
    assert hist.valid_count == 1


def test_summarize_counts_vouches_correctly(two_agents_and_a_review):
    alice, bob, actions = two_agents_and_a_review
    a_summary = summarize(alice.xonly_pubkey_hex, actions)
    assert a_summary.total_actions == 1
    assert a_summary.type_counts == {"review": 1}
    assert a_summary.vouches_received_from == {bob.xonly_pubkey_hex}
    assert a_summary.vouches_given_to == set()
    assert a_summary.disputes_received_from == set()

    b_summary = summarize(bob.xonly_pubkey_hex, actions)
    assert b_summary.total_actions == 1
    assert b_summary.vouches_given_to == {alice.xonly_pubkey_hex}
    assert b_summary.vouches_received_from == set()


def test_summarize_skips_dangling_vouches():
    """A vouch whose parent isn't in the corpus must NOT count."""
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    vouch = make_action(
        agent_pubkey_hex=bob.xonly_pubkey_hex,
        action_type="vouch", target="dd" * 32,
        parent_action="dd" * 32,  # references a non-existent action
    )
    signed_vouch = sign_action(vouch, bob)
    summ = summarize(alice.xonly_pubkey_hex, [signed_vouch])
    assert summ.vouches_received_from == set()


def test_summarize_skips_vouch_with_invalid_parent_sig():
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    review = make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="review", target="x", ts=1,
    )
    signed_review = sign_action(review, alice)
    # Tamper the review so its signature fails.
    forged_review = copy.deepcopy(signed_review)
    forged_review.action.target = "y"

    vouch = make_action(
        agent_pubkey_hex=bob.xonly_pubkey_hex,
        action_type="vouch", target=signed_review.id,
        parent_action=signed_review.id,
    )
    signed_vouch = sign_action(vouch, bob)
    summ = summarize(alice.xonly_pubkey_hex, [forged_review, signed_vouch])
    assert summ.vouches_received_from == set(), \
        "vouches over an invalid parent must not count"


def test_dispute_tracked_separately(two_agents_and_a_review):
    alice, bob, actions = two_agents_and_a_review
    charlie = OracleKey.generate()
    dispute = make_action(
        agent_pubkey_hex=charlie.xonly_pubkey_hex,
        action_type="dispute", target=actions[0].id,
        parent_action=actions[0].id,
    )
    actions = actions + [sign_action(dispute, charlie)]
    a_summary = summarize(alice.xonly_pubkey_hex, actions)
    assert a_summary.disputes_received_from == {charlie.xonly_pubkey_hex}


def test_vouch_graph_in_out_degrees(two_agents_and_a_review):
    alice, bob, actions = two_agents_and_a_review
    g = build_vouch_graph(actions)
    assert g.in_degree(alice.xonly_pubkey_hex) == 1
    assert g.out_degree(bob.xonly_pubkey_hex) == 1
    assert g.in_degree(bob.xonly_pubkey_hex) == 0
    assert g.out_degree(alice.xonly_pubkey_hex) == 0


def test_vouch_graph_self_vouches_excluded():
    """An agent vouching for their own action must not inflate their in-degree."""
    alice = OracleKey.generate()
    review = make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="review", target="x",
    )
    signed_review = sign_action(review, alice)
    self_vouch = make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="vouch", target=signed_review.id,
        parent_action=signed_review.id,
    )
    signed_self_vouch = sign_action(self_vouch, alice)
    g = build_vouch_graph([signed_review, signed_self_vouch])
    assert g.in_degree(alice.xonly_pubkey_hex) == 0


def test_vouch_graph_dedupes_repeat_vouches():
    """Bob vouches for Alice's review twice: in-degree is 1, not 2."""
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    review = sign_action(make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="review", target="x", ts=1,
    ), alice)
    vouch1 = sign_action(make_action(
        agent_pubkey_hex=bob.xonly_pubkey_hex,
        action_type="vouch", target=review.id,
        parent_action=review.id, ts=2,
    ), bob)
    vouch2 = sign_action(make_action(
        agent_pubkey_hex=bob.xonly_pubkey_hex,
        action_type="vouch", target=review.id,
        parent_action=review.id, ts=3,
    ), bob)
    g = build_vouch_graph([review, vouch1, vouch2])
    assert g.in_degree(alice.xonly_pubkey_hex) == 1  # bob counted once
