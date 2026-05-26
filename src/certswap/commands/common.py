"""Helpers shared by the plan / apply / verify command implementations."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from certswap.drivers.base import ApplyResult, Plan, VerifyResult
from certswap.ingest import IngestError, ingest
from certswap.models import CertBundle

console = Console()


def resolve_password(password_env: str | None, password_stdin: bool) -> bytes | None:
    if password_env and password_stdin:
        raise typer.BadParameter(
            "use either --password-env or --password-stdin, not both"
        )
    if password_env:
        value = os.environ.get(password_env)
        if value is None:
            raise typer.BadParameter(f"env var {password_env!r} is not set")
        return value.encode("utf-8")
    if password_stdin:
        return sys.stdin.read().rstrip("\n").encode("utf-8")
    return None


def load_bundle(
    bundle_path: Path,
    *,
    password: bytes | None,
    key: Path | None,
    chain: Path | None,
) -> CertBundle:
    try:
        return ingest(
            bundle_path,
            password=password,
            key_path=key,
            chain_path=chain,
        )
    except (IngestError, ValueError) as exc:
        typer.echo(f"ingest failed: {exc}", err=True)
        raise typer.Exit(code=30) from exc


def confirm_or_exit(message: str, *, yes: bool, json_out: bool) -> None:
    """Prompt for confirmation unless --yes is given.

    `--json` implies non-interactive: it acts like `--yes`. We never mix
    JSON output with an interactive prompt.
    """
    if yes or json_out:
        return
    if not typer.confirm(message, default=False):
        typer.echo("aborted", err=True)
        raise typer.Exit(code=0)


def render_plan(plan: Plan, *, json_out: bool) -> None:
    if json_out:
        typer.echo(json.dumps(plan.model_dump(), indent=2, default=str))
        return

    console.print(
        f"[bold]Plan[/bold] for driver=[cyan]{plan.driver}[/cyan] "
        f"target=[cyan]{plan.identifier}[/cyan]"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=3)
    table.add_column("Step")
    table.add_column("Before", style="yellow")
    table.add_column("Would do", style="green")
    for idx, step in enumerate(plan.steps, start=1):
        table.add_row(
            str(idx),
            step.description,
            step.before or "—",
            step.would_do or "—",
        )
    console.print(table)
    for w in plan.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")
    for b in plan.blockers:
        console.print(f"[red]blocker:[/red] {b}")


def render_apply(result: ApplyResult, *, json_out: bool) -> None:
    if json_out:
        typer.echo(json.dumps(result.model_dump(), indent=2, default=str))
        return

    console.print(
        f"[bold]Apply[/bold] driver=[cyan]{result.driver}[/cyan] "
        f"target=[cyan]{result.identifier}[/cyan] exit={result.exit_code}"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=3)
    table.add_column("Step")
    table.add_column("Before", style="yellow")
    table.add_column("After", style="green")
    table.add_column("ms", justify="right", style="dim")
    table.add_column("OK")
    for idx, step in enumerate(result.steps, start=1):
        table.add_row(
            str(idx),
            step.description,
            step.before or "—",
            step.after or "—",
            str(step.duration_ms),
            "[green]✓[/green]" if step.ok else f"[red]✗ {step.error or ''}[/red]",
        )
    console.print(table)
    if result.verify is not None:
        render_verify(result.verify, json_out=False)


def render_verify(result: VerifyResult, *, json_out: bool) -> None:
    if json_out:
        typer.echo(json.dumps(result.model_dump(), indent=2, default=str))
        return

    table = Table(show_header=True, header_style="bold", title="Verification")
    table.add_column("Check")
    table.add_column("OK")
    table.add_column("Detail", style="dim")
    for chk in result.checks:
        table.add_row(
            chk.name,
            "[green]✓[/green]" if chk.ok else "[red]✗[/red]",
            chk.detail or "",
        )
    console.print(table)
    if not result.ok:
        console.print("[red]verify FAILED[/red]")


def build_local_options(
    dest: Path,
    cert_name: str,
    combined: bool,
    force: bool,
) -> dict[str, Any]:
    return {
        "dest": str(dest),
        "cert_name": cert_name,
        "combined": combined,
        "force": force,
    }
