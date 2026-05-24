"""Nostr publication format for AgentActions.

Agent actions are wrapped in NIP-01 regular events (kind 1990) — NOT
parameterized-replaceable, because actions are non-repudiable. Once
published, an agent cannot revise its past actions; it can only
publish a counter-action (e.g., dispute its own earlier vouch).

The event's content is the base64-encoded SignedAction JSON. The event
is signed by the SAME key that signed the action, so verifying the
Nostr event AND verifying the embedded SignedAction is checking the
same key twice on two related digests — defense in depth against any
single layer being malformed.

Tags carried in the Nostr event for relay-side filtering:
  ["d", action_id]                         deterministic event identifier
  ["t", action_type]                       query by action type
  ["e", parent_action_id]  (optional)      query for vouches of an action

We deliberately do NOT emit a `["p", agent_pubkey]` self-pointing
tag — per NIP-01 "p" references OTHER pubkeys (mentions/replies).
The acting agent is already queryable via the standard `authors`
REQ filter on the event's pubkey field.
"""

from __future__ import annotations

import base64
from typing import Any

from veritas.crypto import OracleKey
from veritas.nostr import NostrEvent

from .action import SignedAction, action_id


KIND_AGENT_ACTION = 1990


def build_action_event(signed: SignedAction, key: OracleKey) -> NostrEvent:
    """Wrap a SignedAction as a NIP-01 kind-1990 event signed by `key`."""
    if signed.action.agent != key.xonly_pubkey_hex:
        raise ValueError(
            "signing key pubkey does not match the action's agent"
        )
    aid = action_id(signed.action)
    tags: list[list[str]] = [
        ["d", aid],
        ["t", signed.action.action_type],
    ]
    if signed.action.parent_action:
        tags.append(["e", signed.action.parent_action])

    content = base64.b64encode(signed.to_json().encode("utf-8")).decode("ascii")
    evt = NostrEvent(
        pubkey=key.xonly_pubkey_hex,
        created_at=signed.action.ts,
        kind=KIND_AGENT_ACTION,
        tags=tags,
    )
    evt.content = content
    return evt.sign(key)


def decode_action_event(
    evt: NostrEvent, *, verify_outer: bool = True,
) -> SignedAction:
    """Inverse of build_action_event. Raises ValueError on malformed input.

    By default we verify BOTH:
      1. The OUTER Nostr event signature (event id + Schnorr sig +
         pubkey) — prevents an attacker re-wrapping a valid SignedAction
         under an unrelated Nostr key, which would otherwise fool a
         caller into trusting the transport-layer claim "agent X
         published this at created_at=T on relay R".
      2. The INNER SignedAction signature — caller asks for a decoded
         object; we should not return one whose inner sig fails verify.
         Without this, a torn-write or attacker-crafted event with a
         valid outer wrapper but corrupted inner sig would silently
         return a SignedAction that callers might trust.

    Pass `verify_outer=False` only when you've already verified BOTH
    layers separately (or genuinely don't care about the outer
    authorship + inner authenticity claims).
    """
    if evt.kind != KIND_AGENT_ACTION:
        raise ValueError(
            f"expected kind {KIND_AGENT_ACTION}, got {evt.kind}"
        )
    if verify_outer and not evt.verify():
        raise ValueError("outer Nostr event signature is invalid")
    raw = base64.b64decode(evt.content)
    sa = SignedAction.from_json(raw)
    if verify_outer:
        if sa.action.agent != evt.pubkey:
            raise ValueError(
                "inner action.agent does not match outer Nostr event pubkey"
            )
        if not sa.verify():
            raise ValueError("inner SignedAction signature is invalid")
    return sa


def extract_parent_id(evt: NostrEvent) -> str | None:
    """Pull the parent action_id out of an event's e-tag (if any)."""
    for t in evt.tags:
        if len(t) >= 2 and t[0] == "e":
            return t[1]
    return None
