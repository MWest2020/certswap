from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands.common import (
    build_local_options,
    load_bundle,
    render_plan,
    resolve_password,
)
from certswap.commands.plan._app import plan_app
from certswap.drivers.base import TargetContext, get_driver


@plan_app.command(name="local")
def plan_local(
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
    json_out: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON")] = False,
) -> None:
    """Dry-run a local-filesystem deployment."""
    password = resolve_password(password_env, password_stdin)
    cb = load_bundle(bundle, password=password, key=key, chain=chain)
    ctx = TargetContext(
        driver="local",
        identifier=str(dest),
        options=build_local_options(dest, cert_name, combined, force),
    )
    plan = get_driver("local").plan(cb, ctx)
    render_plan(plan, json_out=json_out)
    if plan.is_blocked:
        raise typer.Exit(code=10)
