"""Shared ``apply`` ceremony: plan → confirm → apply → evidence → state.

Each per-driver ``apply <driver>`` command builds a ``TargetContext`` and a
``CertBundle`` and delegates the rest to :func:`run_apply`. This keeps the
12 lines that vary (driver flags) per-driver while the 30 lines that don't
live exactly once.
"""

from __future__ import annotations

from pathlib import Path

import typer

from certswap.commands.common import confirm_or_exit, render_apply, render_plan
from certswap.drivers.base import EgressDriver, TargetContext
from certswap.evidence import build_record, default_evidence_root, write_evidence
from certswap.models import CertBundle
from certswap.state import StateEntry
from certswap.state import append as state_append


def run_apply(
    driver: EgressDriver,
    ctx: TargetContext,
    bundle: CertBundle,
    *,
    confirm_msg: str,
    yes: bool,
    json_out: bool,
    evidence_dir: Path | None,
) -> None:
    plan = driver.plan(bundle, ctx)
    if plan.is_blocked:
        render_plan(plan, json_out=json_out)
        raise typer.Exit(code=10)
    if not json_out:
        render_plan(plan, json_out=False)
    confirm_or_exit(confirm_msg, yes=yes, json_out=json_out)

    result = driver.apply(bundle, ctx)
    render_apply(result, json_out=json_out)

    record = build_record(bundle, ctx, result)
    written = write_evidence(record, evidence_dir or default_evidence_root())
    if not json_out:
        typer.echo(f"evidence: {written}")
    if result.exit_code == 0:
        state_append(
            StateEntry(
                timestamp=record.timestamp_utc,
                target=ctx.driver,
                identifier=ctx.identifier,
                fingerprint=bundle.fingerprint_sha256(),
                not_after=bundle.not_after(),
                evidence_dir=str(written),
            )
        )
    if result.exit_code != 0:
        raise typer.Exit(code=result.exit_code)
