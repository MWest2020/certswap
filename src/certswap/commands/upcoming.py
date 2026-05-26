"""`certswap upcoming` — list deployed certs that expire within N days."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from certswap.state import StateEntry, load, upcoming

console = Console()


def _days_remaining(entry: StateEntry) -> int:
    return (entry.not_after - datetime.now(UTC)).days


def upcoming_command(
    within_days: Annotated[
        int, typer.Option("--within-days", help="Window in days (default 60)")
    ] = 60,
    state_path: Annotated[
        Path | None,
        typer.Option(
            "--state",
            help="State file path (default: ~/.certswap/state.json)",
            exists=False,
        ),
    ] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON")
    ] = False,
) -> None:
    """Show every deployment whose cert expires within ``--within-days``."""
    state = load(state_path)
    entries = upcoming(within_days=within_days, state=state)

    if json_out:
        payload = {
            "within_days": within_days,
            "now_utc": datetime.now(UTC).isoformat(),
            "deployments": [
                {
                    **e.model_dump(mode="json"),
                    "days_remaining": _days_remaining(e),
                }
                for e in entries
            ],
        }
        typer.echo(json.dumps(payload, indent=2, default=str))
        return

    if not entries:
        console.print(
            f"[green]none expiring within {within_days} days.[/green]"
        )
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Days", justify="right", style="bold")
    table.add_column("Target")
    table.add_column("Identifier")
    table.add_column("Expires (UTC)")
    table.add_column("Fingerprint", style="dim")
    for e in entries:
        days = _days_remaining(e)
        days_render = f"[red]{days}[/red]" if days < 14 else str(days)
        table.add_row(
            days_render,
            e.target,
            e.identifier,
            e.not_after.strftime("%Y-%m-%d"),
            e.fingerprint[:16] + "…",
        )
    console.print(table)
