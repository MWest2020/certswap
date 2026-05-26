"""`certswap verify <driver>` — post-check a target without supplying a bundle."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands.common import build_local_options, render_verify
from certswap.drivers.base import TargetContext, get_driver

verify_app = typer.Typer(name="verify", help="Post-check a target without supplying a bundle.")


@verify_app.command(name="local")
def verify_local(
    dest: Annotated[Path, typer.Option("--dest", help="Destination directory")],
    cert_name: Annotated[
        str, typer.Option("--cert-name", help="Basename for cert/key files")
    ] = "fullchain",
    combined: Annotated[
        bool, typer.Option("--combined", help="Check the combined PEM as well")
    ] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON")] = False,
) -> None:
    """Verify the cert files exist (and are non-empty) at ``--dest``."""
    ctx = TargetContext(
        driver="local",
        identifier=str(dest),
        options=build_local_options(dest, cert_name, combined, force=False),
    )
    result = get_driver("local").verify(ctx)
    render_verify(result, json_out=json_out)
    if not result.ok:
        raise typer.Exit(code=60)
