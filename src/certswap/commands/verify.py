"""`certswap verify <driver>` — post-check a target without supplying a bundle."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands.common import build_local_options, build_ssh_options, render_verify
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


@verify_app.command(name="ssh")
def verify_ssh(
    host: Annotated[str, typer.Option("--host")],
    cert_dest: Annotated[str | None, typer.Option("--cert-dest")] = None,
    key_dest: Annotated[str | None, typer.Option("--key-dest")] = None,
    chain_dest: Annotated[str | None, typer.Option("--chain-dest")] = None,
    combined_dest: Annotated[str | None, typer.Option("--combined-dest")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Verify the cert files exist on the remote host."""
    options = build_ssh_options(
        host=host,
        cert_dest=cert_dest,
        key_dest=key_dest,
        chain_dest=chain_dest,
        combined_dest=combined_dest,
        mode_cert=0o644,
        mode_key=0o600,
        owner=None,
        group=None,
        reload_cmd=None,
        pre_check_cmd=None,
        post_check_cmd=None,
    )
    ident = cert_dest or combined_dest or key_dest or host
    ctx = TargetContext(driver="ssh", identifier=f"{host}:{ident}", options=options)
    result = get_driver("ssh").verify(ctx)
    render_verify(result, json_out=json_out)
    if not result.ok:
        raise typer.Exit(code=60)
