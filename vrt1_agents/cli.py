"""vrt1-agent — CLI for agent-action attestations.

Subcommands:
  sign     — sign an action from a JSON spec file
  verify   — verify a saved SignedAction
  inspect  — pretty-print a SignedAction's contents
  reputation — aggregate a directory of SignedActions and dump the
               reputation summary for a given agent
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from veritas.crypto import OracleKey

from .action import (
    AgentAction,
    SignedAction,
    action_id,
    make_action,
    sign_action,
)
from .reputation import (
    build_vouch_graph,
    history_for,
    summarize,
)


console = Console()


@click.group()
def cli() -> None:
    """vrt1-agent — sign and reason about agent-action attestations."""


@cli.command()
@click.option("--key", "key_path", type=click.Path(exists=True), required=True,
              help="Hex-encoded BIP-340 private key file (32 bytes hex).")
@click.option("--spec", "spec_path", type=click.Path(exists=True), required=True,
              help="JSON file describing the action to sign.")
@click.option("--out", type=click.Path(), default=None,
              help="Write the signed action JSON to this path (default: stdout).")
def sign(key_path: str, spec_path: str, out: str | None) -> None:
    """Sign an action.

    The --spec JSON must look like:
      {
        "action_type": "review",
        "target": "https://example.com/article-42",
        "params": {"score": 4},
        "outcome": {"verdict": "trustworthy"},
        "parent_action": null
      }

    `agent` is derived from the supplied key, so it is NOT required in
    the spec; if present, it must match the key's pubkey or signing fails.
    """
    try:
        key = OracleKey.from_hex(Path(key_path).read_text().strip())
    except ValueError as e:
        raise click.ClickException(f"invalid key file: {e}")
    try:
        spec = json.loads(Path(spec_path).read_text())
    except json.JSONDecodeError as e:
        raise click.ClickException(f"invalid spec JSON: {e}")

    if "action_type" not in spec or "target" not in spec:
        raise click.ClickException("spec must include action_type and target")

    if spec.get("agent") and spec["agent"] != key.xonly_pubkey_hex:
        raise click.ClickException(
            "spec.agent does not match the supplied key's pubkey"
        )

    action = make_action(
        agent_pubkey_hex=key.xonly_pubkey_hex,
        action_type=spec["action_type"],
        target=spec["target"],
        params=spec.get("params") or {},
        outcome=spec.get("outcome") or {},
        ts=spec.get("ts"),
        parent_action=spec.get("parent_action"),
    )
    signed = sign_action(action, key)
    body = signed.to_json()

    if out:
        Path(out).write_text(body)
        console.print(f"[green]signed[/green] → {out}")
        console.print(f"action_id: [yellow]{signed.id}[/yellow]")
    else:
        click.echo(body)


@cli.command()
@click.argument("action_file", type=click.Path(exists=True))
def verify(action_file: str) -> None:
    """Verify a SignedAction's Schnorr signature.

    Exits 0 on VALID, 1 on INVALID — so scripts can gate on the result
    (`vrt1-agent verify a.json && deploy.sh`).
    """
    try:
        signed = SignedAction.from_json(Path(action_file).read_text())
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        raise click.ClickException(f"invalid signed-action file: {e}")
    ok = signed.verify()
    console.print(Panel.fit(
        "[bold green]VALID[/bold green]" if ok else "[bold red]INVALID[/bold red]",
        title=f"action {signed.id[:16]}…", border_style="green" if ok else "red",
    ))
    sys.exit(0 if ok else 1)


@cli.command()
@click.argument("action_file", type=click.Path(exists=True))
def inspect(action_file: str) -> None:
    """Pretty-print a SignedAction."""
    try:
        signed = SignedAction.from_json(Path(action_file).read_text())
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        raise click.ClickException(f"invalid signed-action file: {e}")
    a = signed.action
    t = Table(title=f"SignedAction {signed.id[:16]}…", show_header=False)
    t.add_row("agent", a.agent)
    t.add_row("type", a.action_type)
    t.add_row("target", a.target)
    t.add_row("ts", str(a.ts))
    if a.parent_action:
        t.add_row("parent", a.parent_action)
    t.add_row("params", json.dumps(a.params))
    t.add_row("outcome", json.dumps(a.outcome))
    t.add_row("sig", signed.sig[:32] + "…" + signed.sig[-16:])
    t.add_row("valid?", "[green]yes[/green]" if signed.verify() else "[red]no[/red]")
    console.print(t)


def _load_corpus(
    corpus_dir: str,
) -> tuple[list[SignedAction], list[tuple[Path, str]]]:
    """Load actions from a directory, returning (loaded, errors).

    Errors are (path, reason) tuples for any file that failed to
    parse — surfaced to the user instead of silently dropped, so
    forensic blind spots don't mask attacks or torn writes.
    """
    actions: list[SignedAction] = []
    errors: list[tuple[Path, str]] = []
    for p in sorted(Path(corpus_dir).glob("*.json")):
        try:
            actions.append(SignedAction.from_json(p.read_text()))
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            errors.append((p, f"{type(e).__name__}: {e}"))
    return actions, errors


@cli.command()
@click.option("--corpus", type=click.Path(exists=True, file_okay=False), required=True,
              help="Directory containing one *.json SignedAction per file.")
@click.option("--agent", required=True, help="x-only pubkey hex of the agent to summarize.")
def reputation(corpus: str, agent: str) -> None:
    """Aggregate a corpus and dump reputation for one agent."""
    actions, errors = _load_corpus(corpus)
    if not actions:
        raise click.ClickException(f"no parseable SignedActions found in {corpus}")

    hist = history_for(agent, actions)
    summ = summarize(agent, actions)
    graph = build_vouch_graph(actions)

    summary_lines = [
        f"Corpus: {len(actions)} signed actions",
        f"Agent:  {agent}",
    ]
    if errors:
        summary_lines.append(
            f"[yellow]skipped:[/yellow] {len(errors)} unparseable file(s) "
            "(use --verbose for paths)"
        )
    console.print(Panel.fit("\n".join(summary_lines), border_style="cyan"))

    if errors:
        # Escape Rich markup chars in filenames AND exception messages.
        # A corpus file named `01[bold].json` or an exception message
        # containing `[`/`]` would otherwise break Rich's parser and
        # render unpredictably.
        from rich.markup import escape as _rich_escape
        for p, reason in errors[:5]:
            console.print(
                f"  [yellow]skipped[/yellow] {_rich_escape(p.name)}: "
                f"{_rich_escape(reason)}",
                style="dim",
            )
        if len(errors) > 5:
            console.print(f"  [yellow]...and {len(errors) - 5} more[/yellow]", style="dim")

    t = Table(title="History")
    t.add_column("ts"); t.add_column("type"); t.add_column("target"); t.add_column("valid?")
    for e in hist.entries:
        t.add_row(
            str(e.signed.action.ts),
            e.signed.action.action_type,
            (e.signed.action.target[:48] + "…") if len(e.signed.action.target) > 48 else e.signed.action.target,
            "[green]✓[/green]" if e.valid else "[red]✗[/red]",
        )
    if not hist.entries:
        t.add_row("—", "—", "no actions found for this agent", "—")
    console.print(t)

    t = Table(title="Summary")
    t.add_row("valid actions", str(summ.total_actions))
    t.add_row("by type", json.dumps(summ.type_counts, sort_keys=True))
    t.add_row("vouches received from", str(len(summ.vouches_received_from)))
    t.add_row("vouches given to",      str(len(summ.vouches_given_to)))
    t.add_row("disputes received from", str(len(summ.disputes_received_from)))
    t.add_row("disputes given to",      str(len(summ.disputes_given_to)))
    console.print(t)

    t = Table(title="Vouch graph metrics")
    t.add_row("in-degree (vouches received)", str(graph.in_degree(agent)))
    t.add_row("out-degree (vouches given)",   str(graph.out_degree(agent)))
    t.add_row("disputes against this agent",  str(graph.disputes_against(agent)))
    console.print(t)


def main() -> None:
    """Entry point for the `vrt1-agent` console script."""
    cli()


if __name__ == "__main__":
    main()
