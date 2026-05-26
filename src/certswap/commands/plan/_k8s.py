from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands.common import (
    build_k8s_options,
    load_bundle,
    render_plan,
    resolve_password,
)
from certswap.commands.plan._app import plan_app
from certswap.drivers.base import TargetContext, get_driver


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
    argocd_app: Annotated[
        str | None,
        typer.Option("--argocd-app", help="ArgoCD Application name to coordinate with"),
    ] = None,
    argocd_namespace: Annotated[
        str, typer.Option("--argocd-namespace", help="Namespace where the Application lives")
    ] = "argocd",
    argocd_wait_seconds: Annotated[
        float, typer.Option("--argocd-wait", help="Seconds to wait before verify (apply only)")
    ] = 60.0,
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
        argocd_app=argocd_app,
        argocd_namespace=argocd_namespace,
        argocd_wait_seconds=argocd_wait_seconds,
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
