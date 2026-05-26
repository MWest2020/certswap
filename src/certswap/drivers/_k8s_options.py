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
        )
