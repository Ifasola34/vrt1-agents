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

    By default we verify the OUTER Nostr event signature (event id +
    Schnorr sig + pubkey) before extracting the inner SignedAction.
    This prevents an attacker from re-wrapping a valid SignedAction in
    a Nostr event signed by an unrelated key (which would otherwise be
    accepted as "this agent published this action at created_at=T on
    relay R" — a forged transport-layer claim).

    Pass `verify_outer=False` only when you've already verified the
    Nostr layer separately (or genuinely don't care about the outer
    authorship claim).
    """
    if evt.kind != KIND_AGENT_ACTION:
        raise ValueError(
            f"expected kind {KIND_AGENT_ACTION}, got {evt.kind}"
        )
    if verify_outer and not evt.verify():
        raise ValueError("outer Nostr event signature is invalid")
    raw = base64.b64decode(evt.content)
    sa = SignedAction.from_json(raw)
    if verify_outer and sa.action.agent != evt.pubkey:
        raise ValueError(
            "inner action.agent does not match outer Nostr event pubkey"
        )
    return sa


def extract_parent_id(evt: NostrEvent) -> str | None:
    """Pull the parent action_id out of an event's e-tag (if any)."""
    for t in evt.tags:
        if len(t) >= 2 and t[0] == "e":
            return t[1]
    return None
