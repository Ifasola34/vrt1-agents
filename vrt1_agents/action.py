"""AgentAction — what an autonomous agent signs to record what it did.

An action is a structured, time-stamped, schema-versioned event. The
agent signs it with its own BIP-340 Schnorr key (the same key it uses
on Nostr — no new curves, no new identities). Anyone with the agent's
x-only pubkey can verify the action came from that agent and hasn't
been edited.

Actions can chain: a "vouch" action references the action_id it vouches
for via parent_action. This builds a verifiable peer graph — the
substrate for reputation aggregation in reputation.py.

We sit on top of VERITAS primitives (tagged_hash, schnorr_sign,
schnorr_verify) — same crypto, different domain tag, different payload
schema. An agent action is NOT a VERITAS inference attestation; it's
its own object, deliberately parallel rather than nested so the
schemas can evolve independently.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from veritas.crypto import (
    OracleKey,
    schnorr_sign,
    schnorr_verify,
    tagged_hash,
)


ACTION_TAG = "VRT1/agent-action"

# Reserved action types. Open set — agents may define their own — but
# these are the ones reputation.py understands semantically.
KNOWN_TYPES = frozenset({
    "infer",      # ran a model on input, produced output (bridge to VERITAS inference)
    "review",     # examined a target (URL, document, claim) and produced a verdict
    "vouch",      # endorsed another action (parent_action set)
    "dispute",    # rejected another action (parent_action set)
    "trade",      # executed a trade / transfer
    "consume",    # consumed a resource (paid call, energy, compute)
    "message",    # sent a message to another agent
})


def canonical_json(obj: Any) -> bytes:
    """Stable byte encoding — sorted keys, no whitespace, UTF-8 safe.

    Same canonicalization rules VERITAS uses for attestation digests,
    by design: same crypto stack, same domain-separation principles.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass
class AgentAction:
    """One signed-event an agent emits.

    `agent` is the agent's 32-byte x-only Schnorr pubkey, hex-encoded.
    `parent_action` is the action_id of a referenced prior action, or
    None for a standalone action. Action IDs are deterministic: the
    hex of the action_digest (so they're immutable and self-describing).
    """

    agent: str
    action_type: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    outcome: dict[str, Any] = field(default_factory=dict)
    ts: int = 0
    parent_action: str | None = None
    v: int = 1

    def to_payload(self) -> dict[str, Any]:
        d = asdict(self)
        if d.get("parent_action") is None:
            d.pop("parent_action")
        return d

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_payload())


def action_digest(action: AgentAction) -> bytes:
    """The 32-byte BIP-340-tagged hash of the canonical action payload.

    This is what gets Schnorr-signed AND what serves as the action_id
    (when hex-encoded). Two actions with identical content always have
    the same digest — by design, so vouches/disputes can reference
    them deterministically.
    """
    return tagged_hash(ACTION_TAG, action.canonical_bytes())


def action_id(action: AgentAction) -> str:
    """Hex-encoded action digest. Stable, deterministic identifier."""
    return action_digest(action).hex()


@dataclass
class SignedAction:
    action: AgentAction
    sig: str  # 64-byte Schnorr sig, hex

    @property
    def id(self) -> str:
        return action_id(self.action)

    def verify(self) -> bool:
        msg = action_digest(self.action)
        try:
            sig = bytes.fromhex(self.sig)
            pk = bytes.fromhex(self.action.agent)
        except ValueError:
            return False
        return schnorr_verify(msg, sig, pk)

    def to_json(self) -> str:
        return json.dumps(
            {"action": self.action.to_payload(), "sig": self.sig},
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> "SignedAction":
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        d = json.loads(raw)
        a = d["action"]
        return cls(
            action=AgentAction(
                agent=a["agent"],
                action_type=a["action_type"],
                target=a["target"],
                params=a.get("params", {}),
                outcome=a.get("outcome", {}),
                ts=int(a.get("ts", 0)),
                parent_action=a.get("parent_action"),
                v=int(a.get("v", 1)),
            ),
            sig=d["sig"],
        )


def make_action(
    *,
    agent_pubkey_hex: str,
    action_type: str,
    target: str,
    params: dict[str, Any] | None = None,
    outcome: dict[str, Any] | None = None,
    ts: int | None = None,
    parent_action: str | None = None,
) -> AgentAction:
    """Build an AgentAction with sensible defaults."""
    return AgentAction(
        agent=agent_pubkey_hex,
        action_type=action_type,
        target=target,
        params=params or {},
        outcome=outcome or {},
        ts=int(ts if ts is not None else time.time()),
        parent_action=parent_action,
    )


def sign_action(action: AgentAction, key: OracleKey) -> SignedAction:
    """Sign an action with its agent's key.

    Enforces that `action.agent` matches the key's pubkey rather than
    silently overwriting — mismatch is almost always a bug.
    """
    if action.agent != key.xonly_pubkey_hex:
        raise ValueError(
            f"action.agent does not match signing key "
            f"(action={action.agent[:8]}…, key={key.xonly_pubkey_hex[:8]}…)"
        )
    sig = schnorr_sign(action_digest(action), key)
    return SignedAction(action=action, sig=sig.hex())
