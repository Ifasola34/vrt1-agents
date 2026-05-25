# vrt1-agents

[![CI](https://github.com/Ifasola34/vrt1-agents/actions/workflows/ci.yml/badge.svg)](https://github.com/Ifasola34/vrt1-agents/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**Signed agent-action attestations for the [VERITAS](https://github.com/Ifasola34/veritas) (VRT1) protocol.**

Lets autonomous agents cryptographically sign what they did — reviews they made, agents they vouched for, trades they executed, resources they consumed — so any third party can later prove which agent made which claim. Builds the substrate for peer-vouched reputation graphs that no single party controls.

If VERITAS gives oracles a way to sign inference outputs, this gives **agents** a way to sign **everything else**.

---

## What an "action" is

An `AgentAction` is a structured, time-stamped event signed by an agent's own BIP-340 Schnorr key (the same key that identifies it on Nostr). Schema:

```python
@dataclass
class AgentAction:
    agent: str            # x-only pubkey of the acting agent (hex)
    action_type: str      # "review" | "vouch" | "dispute" | "trade" | "infer" | "consume" | "message"
    target: str           # URL, agent pubkey, asset, prior action_id — whatever the action is about
    params: dict          # action-specific arguments
    outcome: dict         # observable result
    ts: int               # unix seconds
    parent_action: str | None  # references a prior action_id (e.g. a vouch's target)
    v: int = 1
```

Actions chain via `parent_action`. A `vouch` action sets `parent_action = id_of_the_action_being_endorsed`. A `dispute` action does the same in reverse. Following the chain builds a directed peer graph — the substrate for the reputation primitives below.

The action_id is the BIP-340 tagged hash (`tagged_hash("VRT1/agent-action", canonical_bytes)`) of the action payload. Deterministic and self-describing: two identical actions always have the same id, so vouches and disputes can reference them unambiguously.

---

## How it works end-to-end

```
   ┌─────────────────────────────┐
   │  AgentAction (dict-shaped)  │
   │  agent, type, target, …     │
   └──────────────┬──────────────┘
                  │  canonical_json
                  ▼
   ┌─────────────────────────────┐
   │  tagged_hash("VRT1/agent-   │ → 32-byte action_digest
   │   action", canonical_bytes) │
   └──────────────┬──────────────┘
                  │  schnorr_sign
                  ▼
   ┌─────────────────────────────┐
   │  SignedAction               │
   │   { action, sig (64B hex) } │
   └──────────────┬──────────────┘
                  │  build_action_event
                  ▼
   ┌─────────────────────────────┐
   │  NIP-01 Nostr event         │
   │  kind 1990  (regular,       │
   │     non-replaceable)        │
   │  tags: d, t, p, e?          │
   └─────────────────────────────┘
```

The same Schnorr key signs the action AND the Nostr event — verifying both is checking the same key twice on two related digests. Defense in depth against any single layer being malformed.

---

## Demo: a two-agent vouch

```python
from veritas.crypto import OracleKey
from vrt1_agents.action import make_action, sign_action
from vrt1_agents.reputation import summarize, build_vouch_graph

alice = OracleKey.generate()
bob   = OracleKey.generate()

# Alice reviews an article.
review = sign_action(make_action(
    agent_pubkey_hex=alice.xonly_pubkey_hex,
    action_type="review",
    target="https://news.example/article-42",
    outcome={"verdict": "trustworthy", "score": 4},
), alice)

# Bob vouches for Alice's review.
vouch = sign_action(make_action(
    agent_pubkey_hex=bob.xonly_pubkey_hex,
    action_type="vouch",
    target=review.id,
    parent_action=review.id,
), bob)

# Anyone with both signed actions can now verify and aggregate:
corpus = [review, vouch]
print(summarize(alice.xonly_pubkey_hex, corpus))
# → ReputationSummary(total_actions=1, type_counts={"review": 1},
#                     vouches_received_from={<bob pubkey>}, …)

g = build_vouch_graph(corpus)
print(g.in_degree(alice.xonly_pubkey_hex))   # 1
print(g.out_degree(bob.xonly_pubkey_hex))    # 1
```

No trusted server. No accounts. Both signatures verify against the agents' public keys, and the corpus is portable — same answer whether it came from a Nostr relay, a local file, or a future browser's local cache.

---

## CLI

```
vrt1-agent sign       --key alice.key --spec review.json --out review.signed.json
vrt1-agent verify     review.signed.json
vrt1-agent inspect    review.signed.json
vrt1-agent reputation --corpus ./actions/ --agent <alice_pubkey_hex>
```

The `sign` spec is a small JSON file:

```json
{
  "action_type": "review",
  "target": "https://news.example/article-42",
  "outcome": {"verdict": "trustworthy", "score": 4}
}
```

`agent` is derived from the supplied key — never put it in the spec.

---

## Install

Requires Python 3.10+ (avoid 3.14 until `coincurve` ships wheels for it).

```bash
git clone https://github.com/Ifasola34/vrt1-agents.git
cd vrt1-agents
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

## What's in the box

| Module | What it does |
|---|---|
| `vrt1_agents.action` | `AgentAction` dataclass, canonical JSON, tagged-hash digest, sign/verify, JSON roundtrip |
| `vrt1_agents.nostr` | Wrap a `SignedAction` as a NIP-01 kind-1990 event with `d`/`t`/`p`/`e` tags for relay-side filtering |
| `vrt1_agents.reputation` | `history_for`, `summarize`, `build_vouch_graph` — pure-function aggregation over a corpus of signed actions |
| `vrt1_agents.cli` | The `vrt1-agent` console script |

Reputation primitives are intentionally **opinion-free** — you get counts, sets, and graph metrics; weighting (PageRank, time decay, domain filters) is the consumer's job. v0.1 ships the substrate, not the policy.

---

## Tests

```bash
$ pytest -v
31 passed in 0.09s
```

Coverage:

- **Action** (8): canonical JSON stability, sign+verify roundtrip, mismatched-agent rejection, post-sign tamper rejection, deterministic action_id, action_id changes on any field change, JSON roundtrip preserves sig, parent_action omitted when None.
- **Nostr** (6): event roundtrip preserves signed action, tags include d/t/p/e, no e-tag when no parent, mismatched-key rejection on build, wrong-kind rejection on decode, parent extraction.
- **Reputation** (10): history sort + filter, invalid-action flagging, vouch counts, dangling-vouch exclusion, vouches-over-invalid-parent exclusion, dispute tracking, in/out-degree correctness, self-vouch exclusion, repeat-vouch dedup.
- **CLI** (7): sign writes valid output, sign rejects wrong-agent spec, sign requires action_type+target, verify reports valid + invalid, reputation aggregates + dumps, empty-corpus error.

---

## Where this fits

**Standalone:** any project that needs portable, peer-verifiable records of what an autonomous agent did. Trading bots that need an audit trail. AI agents that vouch for each other's outputs. Distributed-systems audit logs where you don't trust the central collector.

**Alongside VERITAS:** inference attestations and agent actions are parallel primitives. An inference *output* gets signed by an oracle (VERITAS); an agent *action* — including the meta-action of "I trusted this oracle's output" — gets signed by the agent (this repo). Together they cover both halves of "who claimed what."

**Alongside [vrt1-verifier](https://github.com/Ifasola34/vrt1-verifier):** vrt1-verifier already verifies VERITAS attestations from public infrastructure. The same pattern extends here — an agent-action verifier can fetch kind-1990 events from any Nostr relay and run the same `SignedAction.verify()` you'd run locally.

---

## License

MIT — see [`LICENSE`](LICENSE).
