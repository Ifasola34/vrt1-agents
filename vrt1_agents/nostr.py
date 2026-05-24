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
  ["t", action_type]                       — query by action type
  ["p", agent_pubkey]                      — query by acting agent
  ["e", parent_action_id]  (optional)      — query for vouches of an action
  ["d", action_id]                         — deterministic event identifier
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
        ["p", signed.action.agent],
    ]
    if signed.action.parent_action:
        tags.append(["e", signed.action.parent_action])

    content = base64.b64encode(signed.to_json().encode("utf-8")).decode("ascii")
    evt = NostrEvent(
        pubkey=key.xonly_pubkey_hex,
        created_at=signed.action.ts,
        kind=KIND_AGENT_ACTION,
        tags=tags,
        content=content,
    )
    return evt.sign(key)


def decode_action_event(evt: NostrEvent) -> SignedAction:
    """Inverse of build_action_event. Raises on malformed input."""
    if evt.kind != KIND_AGENT_ACTION:
        raise ValueError(
            f"expected kind {KIND_AGENT_ACTION}, got {evt.kind}"
        )
    raw = base64.b64decode(evt.content)
    return SignedAction.from_json(raw)


def extract_parent_id(evt: NostrEvent) -> str | None:
    """Pull the parent action_id out of an event's e-tag (if any)."""
    for t in evt.tags:
        if len(t) >= 2 and t[0] == "e":
            return t[1]
    return None
