from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands._apply_runner import run_apply
from certswap.commands.apply._app import apply_app
from certswap.commands.common import load_bundle, resolve_password
from certswap.drivers.base import TargetContext, get_driver


@apply_app.command(name="proxmox")
def apply_proxmox(
    bundle: Annotated[Path, typer.Argument(exists=True, readable=True)],
    host: Annotated[str, typer.Option("--host")],
    password_env: Annotated[str | None, typer.Option("--password-env")] = None,
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    key: Annotated[Path | None, typer.Option("--key", exists=True, readable=True)] = None,
    chain_path: Annotated[Path | None, typer.Option("--chain", exists=True, readable=True)] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    evidence_dir: Annotated[Path | None, typer.Option("--evidence-dir")] = None,
) -> None:
    """Apply the bundle to a Proxmox VE node's pveproxy."""
    password = resolve_password(password_env, password_stdin)
    cb = load_bundle(bundle, password=password, key=key, chain=chain_path)
    ctx = TargetContext(
        driver="proxmox", identifier=f"{host}:pveproxy", options={"host": host}
    )
    run_apply(
        get_driver("proxmox"),
        ctx,
        cb,
        confirm_msg=f"Apply to {host} (Proxmox VE)?",
        yes=yes,
        json_out=json_out,
        evidence_dir=evidence_dir,
    )
