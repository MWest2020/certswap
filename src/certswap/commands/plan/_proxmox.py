from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands.common import load_bundle, render_plan, resolve_password
from certswap.commands.plan._app import plan_app
from certswap.drivers.base import TargetContext, get_driver


@plan_app.command(name="proxmox")
def plan_proxmox(
    bundle: Annotated[Path, typer.Argument(exists=True, readable=True)],
    host: Annotated[str, typer.Option("--host")],
    password_env: Annotated[str | None, typer.Option("--password-env")] = None,
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    key: Annotated[Path | None, typer.Option("--key", exists=True, readable=True)] = None,
    chain_path: Annotated[
        Path | None, typer.Option("--chain", exists=True, readable=True)
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Dry-run a Proxmox VE pveproxy cert swap."""
    password = resolve_password(password_env, password_stdin)
    cb = load_bundle(bundle, password=password, key=key, chain=chain_path)
    ctx = TargetContext(
        driver="proxmox", identifier=f"{host}:pveproxy", options={"host": host}
    )
    plan = get_driver("proxmox").plan(cb, ctx)
    render_plan(plan, json_out=json_out)
    if plan.is_blocked:
        raise typer.Exit(code=10)
