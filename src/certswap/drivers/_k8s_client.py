"""Thin facade over the kubernetes client.

Wraps just the operations the driver needs. Tests inject a fake; the
driver never imports ``kubernetes.*`` directly except inside this file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class SecretView:
    name: str
    namespace: str
    type: str
    fingerprint_sha256: str | None  # SHA256 of the cert in tls.crt, if present


@dataclass(frozen=True)
class IngressView:
    name: str
    namespace: str
    hosts: list[str]
    cert_manager_annotation: str | None  # value of cert-manager.io/cluster-issuer, if set


@dataclass(frozen=True)
class CertificateView:
    """The cert-manager.io/v1 Certificate CRD that produces a secret."""

    name: str
    namespace: str
    issuer_ref: str | None  # cluster-issuer / issuer name


class K8sClient(Protocol):
    def current_context(self) -> str: ...

    def namespace_exists(self, namespace: str) -> bool: ...

    def get_secret(self, namespace: str, name: str) -> SecretView | None: ...

    def delete_secret(self, namespace: str, name: str) -> None: ...

    def create_tls_secret(
        self, namespace: str, name: str, cert_pem: bytes, key_pem: bytes
    ) -> None: ...

    def get_ingress(self, namespace: str, name: str) -> IngressView | None: ...

    def strip_ingress_cert_manager_annotation(self, namespace: str, name: str) -> bool: ...

    def find_certificate_for_secret(
        self, namespace: str, secret_name: str
    ) -> CertificateView | None: ...

    def delete_certificate(self, namespace: str, name: str) -> None: ...


def load(context: str | None = None) -> K8sClient:
    """Construct a real K8sClient using the kubernetes Python library.

    Imports kubernetes lazily so test-only paths (which inject a fake)
    never pay the cost.
    """
    from certswap.drivers._k8s_live import LiveK8sClient

    return LiveK8sClient(context=context)


class ClusterContextMismatch(RuntimeError):
    """Raised when --context does not match the active kubeconfig context."""


def verify_context(client: K8sClient, expected: str) -> None:
    actual = client.current_context()
    if actual != expected:
        raise ClusterContextMismatch(
            f"expected kubeconfig context {expected!r}, got {actual!r}"
        )


__all__ = [
    "CertificateView",
    "ClusterContextMismatch",
    "IngressView",
    "K8sClient",
    "SecretView",
    "load",
    "verify_context",
]


def _has_kubernetes_lib() -> bool:
    """For optional callers that want to bail early without importing."""
    try:
        import kubernetes  # noqa: F401

        return True
    except ImportError:  # pragma: no cover
        return False


def assert_kubernetes_installed() -> None:
    if not _has_kubernetes_lib():  # pragma: no cover
        raise RuntimeError("`kubernetes` package not installed")


def _coerce_dict(o: Any) -> dict[str, Any]:
    """Helper used by the live client to normalise objects to plain dicts."""
    if isinstance(o, dict):
        return o
    if hasattr(o, "to_dict"):
        d = o.to_dict()
        return d if isinstance(d, dict) else {}
    return {}
