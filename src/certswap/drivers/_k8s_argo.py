"""ArgoCD coordination for the k8s driver.

ArgoCD ``selfHeal`` ignores ``ignoreDifferences``, so a cert swap on an
Argo-managed cluster must (1) disable automated sync, (2) ensure the
secret + ingress live under ``ignoreDifferences`` with
``RespectIgnoreDifferences=true``, and (3) re-enable sync with
``selfHeal=false`` after the swap.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from certswap.drivers._k8s_client import ArgoApplicationView, K8sClient
from certswap.drivers._k8s_options import K8sOptions
from certswap.drivers.base import ApplyResult, CheckResult, Plan, PlanStep


def describe(app: ArgoApplicationView) -> str:
    return (
        f"automated={app.automated_sync} selfHeal={app.self_heal} "
        f"syncOptions={list(app.sync_options)} "
        f"ignoreDifferences[{app.ignore_differences_count}]"
    )


def annotate_plan(
    plan: Plan, opts: K8sOptions, client: K8sClient
) -> bool:
    """Add argo pre/post steps to ``plan``. Returns False if blocked."""
    if not opts.argocd_app:
        return True
    argo = client.get_argo_application(opts.argocd_namespace, opts.argocd_app)
    if argo is None:
        plan.blockers.append(
            f"argocd Application {opts.argocd_namespace}/{opts.argocd_app} not found"
        )
        return False
    plan.steps.insert(
        0,
        PlanStep(
            description=f"argocd: disable automated sync + selfHeal on {argo.name}",
            before=describe(argo),
            would_do=(
                "patch Application: automated=null, "
                "RespectIgnoreDifferences=true, "
                "ignoreDifferences+={secret,ingress}"
            ),
        ),
    )
    plan.steps.append(
        PlanStep(
            description=f"argocd: re-enable automated sync (selfHeal=false) on {argo.name}",
            before=None,
            would_do="patch Application: automated.{prune=true, selfHeal=false}",
        )
    )
    return True


def apply_pre(
    result: ApplyResult,
    opts: K8sOptions,
    client: K8sClient,
    *,
    record_step: Callable[[ApplyResult, str, Callable[[], Any]], None],
) -> None:
    """Silence the reconciler before any mutation."""
    if not opts.argocd_app:
        return
    record_step(
        result,
        f"argocd: disable automated sync on {opts.argocd_app}",
        lambda: client.disable_argo_automated_sync(opts.argocd_namespace, opts.argocd_app or ""),
    )
    record_step(
        result,
        f"argocd: set RespectIgnoreDifferences on {opts.argocd_app}",
        lambda: client.set_argo_respect_ignore_differences(
            opts.argocd_namespace,
            opts.argocd_app or "",
            target_secret=opts.secret,
            target_ingress=opts.ingress,
        ),
    )


def apply_post(
    result: ApplyResult,
    opts: K8sOptions,
    client: K8sClient,
    *,
    record_step: Callable[[ApplyResult, str, Callable[[], Any]], None],
) -> None:
    """Re-enable automated sync; selfHeal stays false."""
    if not opts.argocd_app:
        return
    record_step(
        result,
        f"argocd: re-enable automated sync (selfHeal=false) on {opts.argocd_app}",
        lambda: client.re_enable_argo_sync_no_selfheal(
            opts.argocd_namespace, opts.argocd_app or ""
        ),
    )
    if opts.argocd_wait_seconds > 0:
        time.sleep(opts.argocd_wait_seconds)


def verify_checks(opts: K8sOptions, client: K8sClient) -> list[CheckResult]:
    if not opts.argocd_app:
        return []
    argo = client.get_argo_application(opts.argocd_namespace, opts.argocd_app)
    ok = argo is not None and not argo.self_heal
    return [
        CheckResult(
            name=f"argocd {opts.argocd_app} has selfHeal=false",
            ok=ok,
            detail=None if ok else "selfHeal back on or Application gone",
        )
    ]
