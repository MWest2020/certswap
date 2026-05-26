from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands._apply_runner import run_apply
from certswap.commands.apply._app import apply_app
from certswap.commands.common import (
    build_ssh_options,
    load_bundle,
    resolve_password,
)
from certswap.drivers.base import TargetContext, get_driver


@apply_app.command(name="ssh")
def apply_ssh(
    bundle: Annotated[Path, typer.Argument(exists=True, readable=True)],
    host: Annotated[str, typer.Option("--host", help="ssh host or ~/.ssh/config alias")],
    cert_dest: Annotated[str | None, typer.Option("--cert-dest")] = None,
    key_dest: Annotated[str | None, typer.Option("--key-dest")] = None,
    chain_dest: Annotated[str | None, typer.Option("--chain-dest")] = None,
    combined_dest: Annotated[str | None, typer.Option("--combined-dest")] = None,
    mode_cert: Annotated[int, typer.Option("--mode-cert")] = 0o644,
    mode_key: Annotated[int, typer.Option("--mode-key")] = 0o600,
    owner: Annotated[str | None, typer.Option("--owner")] = None,
    group: Annotated[str | None, typer.Option("--group")] = None,
    reload_cmd: Annotated[str | None, typer.Option("--reload")] = None,
    pre_check_cmd: Annotated[str | None, typer.Option("--pre-check")] = None,
    post_check_cmd: Annotated[str | None, typer.Option("--post-check")] = None,
    password_env: Annotated[str | None, typer.Option("--password-env")] = None,
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    key: Annotated[Path | None, typer.Option("--key", exists=True, readable=True)] = None,
    chain: Annotated[Path | None, typer.Option("--chain", exists=True, readable=True)] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    evidence_dir: Annotated[Path | None, typer.Option("--evidence-dir")] = None,
) -> None:
    """Apply the bundle to a remote host via ssh + scp."""
    password = resolve_password(password_env, password_stdin)
    cb = load_bundle(bundle, password=password, key=key, chain=chain)
    options = build_ssh_options(
        host=host,
        cert_dest=cert_dest,
        key_dest=key_dest,
        chain_dest=chain_dest,
        combined_dest=combined_dest,
        mode_cert=mode_cert,
        mode_key=mode_key,
        owner=owner,
        group=group,
        reload_cmd=reload_cmd,
        pre_check_cmd=pre_check_cmd,
        post_check_cmd=post_check_cmd,
    )
    ident = cert_dest or combined_dest or key_dest or host
    ctx = TargetContext(driver="ssh", identifier=f"{host}:{ident}", options=options)
    run_apply(
        get_driver("ssh"),
        ctx,
        cb,
        confirm_msg=f"Apply to {host}?",
        yes=yes,
        json_out=json_out,
        evidence_dir=evidence_dir,
    )
