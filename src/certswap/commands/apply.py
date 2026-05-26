"""`certswap apply <driver>` — execute and write an evidence trail."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands.common import (
    build_k8s_options,
    build_local_options,
    build_ssh_options,
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
    driver = get_driver("ssh")

    plan = driver.plan(cb, ctx)
    if plan.is_blocked:
        render_plan(plan, json_out=json_out)
        raise typer.Exit(code=10)
    if not json_out:
        render_plan(plan, json_out=False)
    confirm_or_exit(f"Apply to {host}?", yes=yes, json_out=json_out)

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


@apply_app.command(name="k8s")
def apply_k8s(
    bundle: Annotated[Path, typer.Argument(exists=True, readable=True)],
    secret: Annotated[str, typer.Option("--secret")],
    namespace: Annotated[str, typer.Option("--namespace", "-n")],
    context: Annotated[str | None, typer.Option("--context")] = None,
    ingress: Annotated[str | None, typer.Option("--ingress")] = None,
    keep_cert_manager: Annotated[bool, typer.Option("--keep-cert-manager")] = False,
    allow_host_mismatch: Annotated[bool, typer.Option("--allow-host-mismatch")] = False,
    argocd_app: Annotated[str | None, typer.Option("--argocd-app")] = None,
    argocd_namespace: Annotated[str, typer.Option("--argocd-namespace")] = "argocd",
    argocd_wait_seconds: Annotated[float, typer.Option("--argocd-wait")] = 60.0,
    password_env: Annotated[str | None, typer.Option("--password-env")] = None,
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    key: Annotated[Path | None, typer.Option("--key", exists=True, readable=True)] = None,
    chain_path: Annotated[Path | None, typer.Option("--chain", exists=True, readable=True)] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    evidence_dir: Annotated[Path | None, typer.Option("--evidence-dir")] = None,
) -> None:
    """Apply the bundle as a kubernetes.io/tls Secret."""
    password = resolve_password(password_env, password_stdin)
    cb = load_bundle(bundle, password=password, key=key, chain=chain_path)
    options = build_k8s_options(
        namespace=namespace,
        secret=secret,
        context=context,
        ingress=ingress,
        keep_cert_manager=keep_cert_manager,
        allow_host_mismatch=allow_host_mismatch,
        argocd_app=argocd_app,
        argocd_namespace=argocd_namespace,
        argocd_wait_seconds=argocd_wait_seconds,
    )
    ctx = TargetContext(
        driver="k8s",
        identifier=f"{namespace}/{secret}@{context or 'current-context'}",
        options=options,
    )
    driver = get_driver("k8s")
    plan = driver.plan(cb, ctx)
    if plan.is_blocked:
        render_plan(plan, json_out=json_out)
        raise typer.Exit(code=10)
    if not json_out:
        render_plan(plan, json_out=False)
    confirm_or_exit(f"Apply to {namespace}/{secret}?", yes=yes, json_out=json_out)

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
