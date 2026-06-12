from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands._apply_runner import run_apply
from certswap.commands.apply._app import apply_app
from certswap.commands.common import (
    build_k8s_options,
    load_bundle,
    resolve_password,
)
from certswap.drivers.base import TargetContext, get_driver


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
    argocd_force_managed: Annotated[
        bool, typer.Option("--argocd-force-managed")
    ] = False,
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
        argocd_force_managed=argocd_force_managed,
    )
    ctx = TargetContext(
        driver="k8s",
        identifier=f"{namespace}/{secret}@{context or 'current-context'}",
        options=options,
    )
    run_apply(
        get_driver("k8s"),
        ctx,
        cb,
        confirm_msg=f"Apply to {namespace}/{secret}?",
        yes=yes,
        json_out=json_out,
        evidence_dir=evidence_dir,
    )
