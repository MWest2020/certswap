"""`certswap apply <driver>` — execute and write an evidence trail."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands.common import (
    build_local_options,
    confirm_or_exit,
    load_bundle,
    render_apply,
    render_plan,
    resolve_password,
)
from certswap.drivers.base import TargetContext, get_driver
from certswap.evidence import build_record, default_evidence_root, write_evidence
from certswap.state import StateEntry
from certswap.state import append as state_append

apply_app = typer.Typer(name="apply", help="Execute a deployment and write evidence.")


@apply_app.command(name="local")
def apply_local(
    bundle: Annotated[Path, typer.Argument(exists=True, readable=True)],
    dest: Annotated[Path, typer.Option("--dest", help="Destination directory")],
    cert_name: Annotated[
        str, typer.Option("--cert-name", help="Basename for cert/key files")
    ] = "fullchain",
    combined: Annotated[
        bool,
        typer.Option(
            "--combined",
            help="Also write a single leaf+chain+key PEM (HAProxy-style)",
        ),
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Allow overwrite of existing files")
    ] = False,
    password_env: Annotated[
        str | None, typer.Option("--password-env", help="Env var holding bundle password")
    ] = None,
    password_stdin: Annotated[
        bool, typer.Option("--password-stdin", help="Read bundle password from stdin")
    ] = False,
    key: Annotated[
        Path | None,
        typer.Option("--key", exists=True, readable=True, help="Private key path"),
    ] = None,
    chain: Annotated[
        Path | None,
        typer.Option(
            "--chain", exists=True, readable=True, help="Chain path (separate-file ingest)"
        ),
    ] = None,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Skip confirmation")
    ] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON")] = False,
    evidence_dir: Annotated[
        Path | None,
        typer.Option(
            "--evidence-dir",
            help="Evidence root directory (default: ~/.certswap/evidence/)",
        ),
    ] = None,
) -> None:
    """Apply the bundle to a local filesystem destination."""
    password = resolve_password(password_env, password_stdin)
    cb = load_bundle(bundle, password=password, key=key, chain=chain)
    ctx = TargetContext(
        driver="local",
        identifier=str(dest),
        options=build_local_options(dest, cert_name, combined, force),
    )
    driver = get_driver("local")

    plan = driver.plan(cb, ctx)
    if plan.is_blocked:
        render_plan(plan, json_out=json_out)
        raise typer.Exit(code=10)

    if not json_out:
        render_plan(plan, json_out=False)
    confirm_or_exit(f"Apply to {dest}?", yes=yes, json_out=json_out)

    result = driver.apply(cb, ctx)
    render_apply(result, json_out=json_out)

    record = build_record(cb, ctx, result)
    written = write_evidence(record, evidence_dir or default_evidence_root())
    if not json_out:
        typer.echo(f"evidence: {written}")

    if result.exit_code == 0:
        state_append(
            StateEntry(
                timestamp=record.timestamp_utc,
                target=ctx.driver,
                identifier=ctx.identifier,
                fingerprint=cb.fingerprint_sha256(),
                not_after=cb.not_after(),
                evidence_dir=str(written),
            )
        )

    if result.exit_code != 0:
        raise typer.Exit(code=result.exit_code)
