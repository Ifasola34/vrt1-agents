"""CLI end-to-end: sign, verify, reputation, against real artifacts on disk."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from veritas.crypto import OracleKey

from vrt1_agents.action import make_action, sign_action
from vrt1_agents.cli import cli


def _write_key(tmp_path: Path, key: OracleKey, name: str = "agent.key") -> Path:
    p = tmp_path / name
    p.write_text(key.privkey.hex() + "\n")
    return p


def _write_spec(tmp_path: Path, spec: dict, name: str = "spec.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(spec))
    return p


def test_sign_writes_valid_signed_action(tmp_path: Path):
    k = OracleKey.generate()
    key_path = _write_key(tmp_path, k)
    spec_path = _write_spec(tmp_path, {
        "action_type": "review",
        "target": "https://example.com/x",
        "outcome": {"verdict": "trustworthy"},
    })
    out_path = tmp_path / "signed.json"

    runner = CliRunner()
    r = runner.invoke(cli, [
        "sign", "--key", str(key_path), "--spec", str(spec_path),
        "--out", str(out_path),
    ])
    assert r.exit_code == 0, r.output
    body = json.loads(out_path.read_text())
    assert body["action"]["agent"] == k.xonly_pubkey_hex
    assert body["action"]["action_type"] == "review"
    assert len(body["sig"]) == 128


def test_sign_rejects_spec_with_wrong_agent(tmp_path: Path):
    k = OracleKey.generate()
    other = OracleKey.generate()
    key_path = _write_key(tmp_path, k)
    spec_path = _write_spec(tmp_path, {
        "agent": other.xonly_pubkey_hex,
        "action_type": "review", "target": "x",
    })
    runner = CliRunner()
    r = runner.invoke(cli, [
        "sign", "--key", str(key_path), "--spec", str(spec_path),
    ])
    assert r.exit_code != 0
    assert "does not match" in r.output


def test_sign_requires_action_type_and_target(tmp_path: Path):
    k = OracleKey.generate()
    key_path = _write_key(tmp_path, k)
    spec_path = _write_spec(tmp_path, {"target": "x"})  # missing action_type
    runner = CliRunner()
    r = runner.invoke(cli, [
        "sign", "--key", str(key_path), "--spec", str(spec_path),
    ])
    assert r.exit_code != 0
    assert "action_type" in r.output


def test_verify_reports_valid_for_honest_action(tmp_path: Path):
    k = OracleKey.generate()
    signed = sign_action(make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x",
    ), k)
    p = tmp_path / "sa.json"
    p.write_text(signed.to_json())

    runner = CliRunner()
    r = runner.invoke(cli, ["verify", str(p)])
    assert r.exit_code == 0
    assert "VALID" in r.output


def test_verify_reports_invalid_for_tampered_action(tmp_path: Path):
    k = OracleKey.generate()
    signed = sign_action(make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x",
    ), k)
    body = json.loads(signed.to_json())
    body["action"]["outcome"] = {"verdict": "tampered"}
    p = tmp_path / "tampered.json"
    p.write_text(json.dumps(body))

    runner = CliRunner()
    r = runner.invoke(cli, ["verify", str(p)])
    # Round-2 fix: verify now exits 1 on INVALID for script-gating.
    assert r.exit_code == 1
    assert "INVALID" in r.output


def test_reputation_surfaces_corpus_load_errors(tmp_path: Path):
    """Round-2 fix: silent skip of malformed files is gone; the
    reputation command now reports how many files failed to parse."""
    k = OracleKey.generate()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    signed = sign_action(make_action(
        agent_pubkey_hex=k.xonly_pubkey_hex,
        action_type="review", target="x",
    ), k)
    (corpus / "01.json").write_text(signed.to_json())
    (corpus / "02_torn.json").write_text('{"act')
    (corpus / "03_wrong_shape.json").write_text('{"hello":"world"}')

    runner = CliRunner()
    r = runner.invoke(cli, ["reputation",
                            "--corpus", str(corpus),
                            "--agent", k.xonly_pubkey_hex])
    assert r.exit_code == 0
    assert "skipped" in r.output.lower()
    assert "2 unparseable" in r.output


def test_reputation_dumps_summary_for_agent(tmp_path: Path):
    alice = OracleKey.generate()
    bob = OracleKey.generate()
    review = sign_action(make_action(
        agent_pubkey_hex=alice.xonly_pubkey_hex,
        action_type="review", target="https://x", ts=1,
    ), alice)
    vouch = sign_action(make_action(
        agent_pubkey_hex=bob.xonly_pubkey_hex,
        action_type="vouch", target=review.id,
        parent_action=review.id, ts=2,
    ), bob)

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "01.json").write_text(review.to_json())
    (corpus / "02.json").write_text(vouch.to_json())

    runner = CliRunner()
    r = runner.invoke(cli, [
        "reputation", "--corpus", str(corpus),
        "--agent", alice.xonly_pubkey_hex,
    ])
    assert r.exit_code == 0, r.output
    # Alice's summary should show 1 valid action + 1 vouch received.
    assert "1" in r.output                       # valid actions count
    assert '"review": 1' in r.output             # type counts JSON
    assert "vouches received" in r.output.lower()


def test_reputation_errors_on_empty_corpus(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    runner = CliRunner()
    r = runner.invoke(cli, [
        "reputation", "--corpus", str(empty),
        "--agent", "ab" * 32,
    ])
    assert r.exit_code != 0
    assert "no parseable" in r.output.lower()
