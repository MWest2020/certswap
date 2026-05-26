from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands._apply_runner import run_apply
from certswap.commands.apply._app import apply_app
from certswap.commands.common import (
    build_local_options,
    load_bundle,
    resolve_password,
)
from certswap.drivers.base import TargetContext, get_driver


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
    password_env: Annotated[str | None, typer.Option("--password-env")] = None,
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    key: Annotated[Path | None, typer.Option("--key", exists=True, readable=True)] = None,
    chain: Annotated[Path | None, typer.Option("--chain", exists=True, readable=True)] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
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
    run_apply(
        get_driver("local"),
        ctx,
        cb,
        confirm_msg=f"Apply to {dest}?",
        yes=yes,
        json_out=json_out,
        evidence_dir=evidence_dir,
    )
