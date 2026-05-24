"""AgentAction core: sign, verify, JSON roundtrip, tamper rejection."""

import json

import pytest

from veritas.crypto import OracleKey

from vrt1_agents.action import (
    SignedAction,
    action_digest,
    action_id,
    canonical_json,
    make_action,
    sign_action,
)


def test_canonical_json_is_stable():
    a = {"b": 2, "a": 1, "nested": [{"y": 4, "x": 5}]}
    b = {"nested": [{"x": 5, "y": 4}], "a": 1, "b": 2}
    assert canonical_json(a) == canonical_json(b)


def test_sign_and_verify_roundtrip():
    key = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=key.xonly_pubkey_hex,
        action_type="review",
        target="https://example.com/x",
        params={"score": 4},
        outcome={"verdict": "trustworthy"},
    )
    signed = sign_action(a, key)
    assert signed.verify()
    assert len(signed.sig) == 128  # 64 bytes hex
    assert signed.id == action_digest(a).hex()


def test_sign_rejects_mismatched_agent():
    k = OracleKey.generate()
    other = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=other.xonly_pubkey_hex,
        action_type="review", target="x",
    )
    with pytest.raises(ValueError, match="does not match"):
        sign_action(a, k)


def test_tampered_action_fails_verification():
    k = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="https://example.com",
        outcome={"verdict": "ok"},
    )
    signed = sign_action(a, k)
    assert signed.verify()
    # Mutate output post-sign.
    signed.action.outcome = {"verdict": "tampered"}
    assert signed.verify() is False


def test_action_id_is_deterministic_for_identical_content():
    k = OracleKey.generate()
    a1 = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="vouch", target="x", ts=1700000000,
    )
    a2 = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="vouch", target="x", ts=1700000000,
    )
    assert action_id(a1) == action_id(a2)


def test_action_id_changes_when_any_field_changes():
    k = OracleKey.generate()
    base_kwargs = dict(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x", ts=1700000000,
    )
    base = action_id(make_action(**base_kwargs))
    assert action_id(make_action(**{**base_kwargs, "target": "y"})) != base
    assert action_id(make_action(**{**base_kwargs, "ts": 1700000001})) != base
    assert action_id(make_action(**{**base_kwargs, "params": {"a": 1}})) != base


def test_json_roundtrip_preserves_signature():
    k = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="vouch", target="abc", parent_action="dd" * 32,
    )
    signed = sign_action(a, k)
    raw = signed.to_json()
    again = SignedAction.from_json(raw)
    assert again.verify()
    assert again.id == signed.id
    assert again.action.parent_action == "dd" * 32


def test_parent_action_absent_when_none():
    k = OracleKey.generate()
    a = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x", parent_action=None,
    )
    assert "parent_action" not in a.to_payload()
    # And the canonical bytes don't mention it.
    assert b"parent_action" not in a.canonical_bytes()
