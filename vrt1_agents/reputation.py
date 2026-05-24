"""Reputation aggregation over a corpus of signed agent actions.

Pure functions — no network, no storage. Caller is responsible for
collecting the SignedAction set (from a Nostr relay, a local file, an
inbox, the future browser, etc.). This module just answers questions
about that set.

What we compute, in order of complexity:

  1. ActionHistory — every action by an agent, in time order, with
     signature-validity flag per entry. Invalid actions are returned
     too, but flagged — so the caller can decide whether to filter or
     show them.

  2. ReputationSummary — counts by action type for one agent, plus
     the set of distinct counterparties who vouched for them, plus
     the set they themselves vouched for.

  3. VouchGraph — directed graph: A -> B means A vouched for an
     action authored by B. Plus simple metrics: in-degree (how many
     distinct agents vouched for you), out-degree (how many distinct
     agents you vouched for).

A trust score is intentionally NOT baked in here. Anyone consuming
these primitives can apply their own weighting (PageRank, time decay,
domain-specific filters). v0.1 ships the substrate, not opinions.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .action import SignedAction, action_id


@dataclass
class ActionHistoryEntry:
    signed: SignedAction
    valid: bool          # Schnorr signature verified
    id: str              # action_id for convenience


@dataclass
class ActionHistory:
    agent: str
    entries: list[ActionHistoryEntry] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def valid_count(self) -> int:
        return sum(1 for e in self.entries if e.valid)


def history_for(
    agent_pubkey_hex: str, actions: Iterable[SignedAction],
) -> ActionHistory:
    """Filter to actions claimed by this agent, sorted by ts ascending.

    Includes actions whose signature is INVALID (with valid=False) so
    callers can see attempted-impersonation attempts; filter them out
    yourself if you want a clean view.
    """
    matches: list[ActionHistoryEntry] = []
    for sa in actions:
        if sa.action.agent != agent_pubkey_hex:
            continue
        matches.append(ActionHistoryEntry(
            signed=sa, valid=sa.verify(), id=sa.id,
        ))
    matches.sort(key=lambda e: e.signed.action.ts)
    return ActionHistory(agent=agent_pubkey_hex, entries=matches)


@dataclass
class ReputationSummary:
    agent: str
    total_actions: int                       # valid actions only
    type_counts: dict[str, int]              # by action_type
    vouches_received_from: set[str]          # agents who vouched for this agent's actions
    vouches_given_to: set[str]               # agents this agent vouched for
    disputes_received_from: set[str]
    disputes_given_to: set[str]


def summarize(
    agent_pubkey_hex: str,
    actions: Iterable[SignedAction],
) -> ReputationSummary:
    """Aggregate one agent's reputation surface from the corpus.

    Only signature-valid actions count. Vouch/dispute links require the
    parent action to exist in the corpus AND be valid, otherwise the
    vouch is dangling and excluded.
    """
    actions = list(actions)
    valid_actions = [sa for sa in actions if sa.verify()]
    by_id: dict[str, SignedAction] = {sa.id: sa for sa in valid_actions}

    my_actions = [sa for sa in valid_actions if sa.action.agent == agent_pubkey_hex]
    type_counts = Counter(sa.action.action_type for sa in my_actions)

    vouches_received: set[str] = set()
    disputes_received: set[str] = set()
    vouches_given: set[str] = set()
    disputes_given: set[str] = set()
    my_ids = {sa.id for sa in my_actions}

    for sa in valid_actions:
        pid = sa.action.parent_action
        if not pid or pid not in by_id:
            continue
        parent = by_id[pid]
        if sa.action.action_type == "vouch":
            if parent.action.agent == agent_pubkey_hex and pid in my_ids:
                vouches_received.add(sa.action.agent)
            if sa.action.agent == agent_pubkey_hex:
                vouches_given.add(parent.action.agent)
        elif sa.action.action_type == "dispute":
            if parent.action.agent == agent_pubkey_hex and pid in my_ids:
                disputes_received.add(sa.action.agent)
            if sa.action.agent == agent_pubkey_hex:
                disputes_given.add(parent.action.agent)

    return ReputationSummary(
        agent=agent_pubkey_hex,
        total_actions=len(my_actions),
        type_counts=dict(type_counts),
        vouches_received_from=vouches_received,
        vouches_given_to=vouches_given,
        disputes_received_from=disputes_received,
        disputes_given_to=disputes_given,
    )


@dataclass
class VouchGraph:
    """Directed graph of vouches.

    edges[A] = set of agent pubkeys A has vouched for.
    Mirror dict in_edges[B] = set of agents who vouched for B.
    Disputes are tracked symmetrically in dispute_edges.
    """
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    in_edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    dispute_edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def out_degree(self, agent: str) -> int:
        return len(self.edges.get(agent, set()))

    def in_degree(self, agent: str) -> int:
        return len(self.in_edges.get(agent, set()))

    def disputes_against(self, agent: str) -> int:
        return sum(1 for s in self.dispute_edges.values() if agent in s)


def build_vouch_graph(actions: Iterable[SignedAction]) -> VouchGraph:
    """From a corpus of signed actions, build the vouch graph.

    Only counts vouches/disputes that:
      - have a valid signature on the vouching action
      - reference an existing parent action in the corpus
      - the parent action's signature is also valid
    """
    actions = list(actions)
    valid = [sa for sa in actions if sa.verify()]
    by_id = {sa.id: sa for sa in valid}
    g = VouchGraph()
    for sa in valid:
        pid = sa.action.parent_action
        if not pid or pid not in by_id:
            continue
        parent = by_id[pid]
        # Self-vouches don't add reputation — same agent on both ends.
        if sa.action.agent == parent.action.agent:
            continue
        if sa.action.action_type == "vouch":
            g.edges[sa.action.agent].add(parent.action.agent)
            g.in_edges[parent.action.agent].add(sa.action.agent)
        elif sa.action.action_type == "dispute":
            g.dispute_edges[sa.action.agent].add(parent.action.agent)
    return g
