"""Options for the k8s driver."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from certswap.drivers.base import TargetContext


@dataclass(frozen=True)
class K8sOptions:
    namespace: str
    secret: str
    context: str | None
    ingress: str | None
    keep_cert_manager: bool
    allow_host_mismatch: bool
    argocd_app: str | None
    argocd_namespace: str
    argocd_wait_seconds: float
    argocd_force_managed: bool

    @classmethod
    def from_context(cls, ctx: TargetContext) -> K8sOptions:
        o: dict[str, Any] = ctx.options
        ns = o.get("namespace")
        secret = o.get("secret")
        if not ns or not secret:
            raise ValueError("k8s driver requires `namespace` and `secret`")
        return cls(
            namespace=str(ns),
            secret=str(secret),
            context=str(o["context"]) if o.get("context") else None,
            ingress=str(o["ingress"]) if o.get("ingress") else None,
            keep_cert_manager=bool(o.get("keep_cert_manager", False)),
            allow_host_mismatch=bool(o.get("allow_host_mismatch", False)),
            argocd_app=str(o["argocd_app"]) if o.get("argocd_app") else None,
            argocd_namespace=str(o.get("argocd_namespace") or "argocd"),
            # `or` would coerce a legitimate 0 to 60; use explicit None check.
            argocd_wait_seconds=(
                60.0
                if o.get("argocd_wait_seconds") is None
                else float(o["argocd_wait_seconds"])
            ),
            argocd_force_managed=bool(o.get("argocd_force_managed", False)),
        )
