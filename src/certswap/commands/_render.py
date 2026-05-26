"""Rich + JSON renderers for Plan / ApplyResult / VerifyResult."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from certswap.drivers.base import ApplyResult, Plan, VerifyResult

console = Console()


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
