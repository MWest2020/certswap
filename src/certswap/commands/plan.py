"""`certswap plan <driver>` — dry-run for each driver."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands.common import (
    build_k8s_options,
    build_local_options,
    build_ssh_options,
    load_bundle,
    render_plan,
    resolve_password,
)
from certswap.drivers.base import TargetContext, get_driver

plan_app = typer.Typer(name="plan", help="Show what apply would do, without changing anything.")


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


@plan_app.command(name="ssh")
def plan_ssh(
    bundle: Annotated[Path, typer.Argument(exists=True, readable=True)],
    host: Annotated[str, typer.Option("--host", help="ssh host or ~/.ssh/config alias")],
    cert_dest: Annotated[
        str | None, typer.Option("--cert-dest", help="Remote path for fullchain PEM")
    ] = None,
    key_dest: Annotated[
        str | None, typer.Option("--key-dest", help="Remote path for private key")
    ] = None,
    chain_dest: Annotated[
        str | None, typer.Option("--chain-dest", help="Remote path for intermediates-only PEM")
    ] = None,
    combined_dest: Annotated[
        str | None,
        typer.Option(
            "--combined-dest", help="Remote path for combined leaf+chain+key PEM (HAProxy)"
        ),
    ] = None,
    mode_cert: Annotated[
        int, typer.Option("--mode-cert", help="Octal mode for cert/chain/combined files")
    ] = 0o644,
    mode_key: Annotated[
        int, typer.Option("--mode-key", help="Octal mode for the private key file")
    ] = 0o600,
    owner: Annotated[
        str | None, typer.Option("--owner", help="chown owner on remote")
    ] = None,
    group: Annotated[
        str | None, typer.Option("--group", help="chown group on remote")
    ] = None,
    reload_cmd: Annotated[
        str | None, typer.Option("--reload", help="Remote reload command (e.g. nginx -s reload)")
    ] = None,
    pre_check_cmd: Annotated[
        str | None, typer.Option("--pre-check", help="Remote pre-check command")
    ] = None,
    post_check_cmd: Annotated[
        str | None, typer.Option("--post-check", help="Remote post-check command")
    ] = None,
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
    """Dry-run an ssh-driven file deployment."""
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
    plan = get_driver("ssh").plan(cb, ctx)
    render_plan(plan, json_out=json_out)
    if plan.is_blocked:
        raise typer.Exit(code=10)


@plan_app.command(name="k8s")
def plan_k8s(
    bundle: Annotated[Path, typer.Argument(exists=True, readable=True)],
    secret: Annotated[str, typer.Option("--secret", help="Target k8s Secret name")],
    namespace: Annotated[str, typer.Option("--namespace", "-n", help="k8s namespace")],
    context: Annotated[
        str | None,
        typer.Option("--context", help="Required kubeconfig context (active context must match)"),
    ] = None,
    ingress: Annotated[
        str | None,
        typer.Option("--ingress", help="Ingress to strip cert-manager annotation from"),
    ] = None,
    keep_cert_manager: Annotated[
        bool,
        typer.Option(
            "--keep-cert-manager",
            help="Leave cert-manager Certificate / Ingress annotation in place",
        ),
    ] = False,
    allow_host_mismatch: Annotated[
        bool,
        typer.Option(
            "--allow-host-mismatch",
            help="Continue even when an Ingress host has no matching SAN",
        ),
    ] = False,
    password_env: Annotated[str | None, typer.Option("--password-env")] = None,
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    key: Annotated[Path | None, typer.Option("--key", exists=True, readable=True)] = None,
    chain_path: Annotated[
        Path | None, typer.Option("--chain", exists=True, readable=True)
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Dry-run a k8s-secret deployment."""
    password = resolve_password(password_env, password_stdin)
    cb = load_bundle(bundle, password=password, key=key, chain=chain_path)
    options = build_k8s_options(
        namespace=namespace,
        secret=secret,
        context=context,
        ingress=ingress,
        keep_cert_manager=keep_cert_manager,
        allow_host_mismatch=allow_host_mismatch,
    )
    ctx = TargetContext(
        driver="k8s",
        identifier=f"{namespace}/{secret}@{context or 'current-context'}",
        options=options,
    )
    plan = get_driver("k8s").plan(cb, ctx)
    render_plan(plan, json_out=json_out)
    if plan.is_blocked:
        raise typer.Exit(code=10)
