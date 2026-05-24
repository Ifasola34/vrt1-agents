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


def test_empty_string_parent_action_normalized_to_none():
    """Round-2 fix: parent_action='' used to survive into the payload
    and hash differently from parent_action=None, breaking the
    deterministic-id contract for semantically equivalent inputs."""
    k = OracleKey.generate()
    a_empty = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x", parent_action="",
    )
    a_none = make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x", parent_action=None,
    )
    assert a_empty.parent_action is None
    assert a_empty.canonical_bytes() == a_none.canonical_bytes()


def test_params_must_be_dict():
    """Direct AgentAction construction (or from_json on attacker input)
    must reject non-dict params/outcome. make_action's defaults coerce
    None to {} so this guards the lower-level constructor."""
    from vrt1_agents.action import AgentAction
    k = OracleKey.generate()
    with pytest.raises(ValueError, match="params must be a dict"):
        AgentAction(
            agent=k.xonly_pubkey_hex,
            action_type="review", target="x",
            params="not-a-dict",  # type: ignore[arg-type]
        )


def test_outcome_must_be_dict():
    from vrt1_agents.action import AgentAction
    k = OracleKey.generate()
    with pytest.raises(ValueError, match="outcome must be a dict"):
        AgentAction(
            agent=k.xonly_pubkey_hex,
            action_type="review", target="x",
            outcome=["list", "not", "dict"],  # type: ignore[arg-type]
        )


def test_from_json_rejects_non_dict_params():
    """Attacker publishes a SignedAction whose params is a string —
    signature would verify (canonical_json serializes anything) but
    downstream consumers expecting dict break. from_json catches it."""
    import json as _json
    k = OracleKey.generate()
    # Build a payload that looks legitimate but has params as a string.
    payload = _json.dumps({
        "action": {
            "agent": k.xonly_pubkey_hex,
            "action_type": "review", "target": "x",
            "params": "not-a-dict",
            "outcome": {},
            "ts": 1700000000,
            "v": 1,
        },
        "sig": "00" * 64,
    })
    with pytest.raises(ValueError, match="params must be a dict"):
        SignedAction.from_json(payload)
