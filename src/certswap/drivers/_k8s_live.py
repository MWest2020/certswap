"""Live kubernetes-client-backed implementation of ``K8sClient``.

Kept in a separate file so the type-level Protocol in ``_k8s_client``
stays import-cheap for tests that inject fakes.
"""

from __future__ import annotations

import base64
import hashlib

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client import ApiException

from certswap.drivers._k8s_client import (
    CertificateView,
    IngressView,
    K8sClient,
    SecretView,
)
from certswap.drivers._k8s_live_argo import ArgoMixin

CERT_MANAGER_GROUP = "cert-manager.io"
CERT_MANAGER_VERSION = "v1"
CERT_MANAGER_PLURAL = "certificates"
CERT_MANAGER_ANNOTATION = "cert-manager.io/cluster-issuer"
CERT_MANAGER_ANNOTATION_ISSUER = "cert-manager.io/issuer"


class LiveK8sClient(ArgoMixin, K8sClient):
    def __init__(self, *, context: str | None = None) -> None:
        if context:
            k8s_config.load_kube_config(context=context)
            self._context_name = context
        else:
            k8s_config.load_kube_config()
            _, active = k8s_config.list_kube_config_contexts()
            self._context_name = active["name"]
        self._core = k8s_client.CoreV1Api()
        self._net = k8s_client.NetworkingV1Api()
        self._cust = k8s_client.CustomObjectsApi()

    def current_context(self) -> str:
        return self._context_name

    def namespace_exists(self, namespace: str) -> bool:
        try:
            self._core.read_namespace(namespace)
            return True
        except ApiException as exc:
            if exc.status == 404:
                return False
            raise

    def get_secret(self, namespace: str, name: str) -> SecretView | None:
        try:
            obj = self._core.read_namespaced_secret(name=name, namespace=namespace)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise
        cert_b64 = (obj.data or {}).get("tls.crt")
        fp: str | None = None
        if cert_b64:
            der_or_pem = base64.b64decode(cert_b64)
            fp = _leaf_fingerprint(der_or_pem)
        return SecretView(
            name=name,
            namespace=namespace,
            type=obj.type or "",
            fingerprint_sha256=fp,
        )

    def delete_secret(self, namespace: str, name: str) -> None:
        try:
            self._core.delete_namespaced_secret(name=name, namespace=namespace)
        except ApiException as exc:
            if exc.status != 404:
                raise

    def create_tls_secret(
        self, namespace: str, name: str, cert_pem: bytes, key_pem: bytes
    ) -> None:
        body = k8s_client.V1Secret(
            metadata=k8s_client.V1ObjectMeta(name=name, namespace=namespace),
            type="kubernetes.io/tls",
            data={
                "tls.crt": base64.b64encode(cert_pem).decode("ascii"),
                "tls.key": base64.b64encode(key_pem).decode("ascii"),
            },
        )
        self._core.create_namespaced_secret(namespace=namespace, body=body)

    def get_ingress(self, namespace: str, name: str) -> IngressView | None:
        try:
            obj = self._net.read_namespaced_ingress(name=name, namespace=namespace)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise
        hosts: list[str] = []
        for rule in obj.spec.rules or []:
            if rule.host:
                hosts.append(rule.host)
        for tls in obj.spec.tls or []:
            for h in tls.hosts or []:
                if h not in hosts:
                    hosts.append(h)
        annos = (obj.metadata.annotations or {}) if obj.metadata else {}
        cm_value = annos.get(CERT_MANAGER_ANNOTATION) or annos.get(
            CERT_MANAGER_ANNOTATION_ISSUER
        )
        return IngressView(
            name=name,
            namespace=namespace,
            hosts=hosts,
            cert_manager_annotation=cm_value,
        )

    def strip_ingress_cert_manager_annotation(self, namespace: str, name: str) -> bool:
        patch: dict[str, object] = {
            "metadata": {
                "annotations": {
                    CERT_MANAGER_ANNOTATION: None,
                    CERT_MANAGER_ANNOTATION_ISSUER: None,
                }
            }
        }
        try:
            self._net.patch_namespaced_ingress(name=name, namespace=namespace, body=patch)
            return True
        except ApiException as exc:
            if exc.status == 404:
                return False
            raise

    def find_certificate_for_secret(
        self, namespace: str, secret_name: str
    ) -> CertificateView | None:
        try:
            listing = self._cust.list_namespaced_custom_object(
                group=CERT_MANAGER_GROUP,
                version=CERT_MANAGER_VERSION,
                namespace=namespace,
                plural=CERT_MANAGER_PLURAL,
            )
        except ApiException as exc:
            if exc.status in (404, 403):
                return None
            raise
        for item in listing.get("items", []):
            spec = item.get("spec") or {}
            if spec.get("secretName") == secret_name:
                meta = item.get("metadata") or {}
                issuer = (spec.get("issuerRef") or {}).get("name")
                return CertificateView(
                    name=meta.get("name", ""), namespace=namespace, issuer_ref=issuer
                )
        return None

    def delete_certificate(self, namespace: str, name: str) -> None:
        try:
            self._cust.delete_namespaced_custom_object(
                group=CERT_MANAGER_GROUP,
                version=CERT_MANAGER_VERSION,
                namespace=namespace,
                plural=CERT_MANAGER_PLURAL,
                name=name,
            )
        except ApiException as exc:
            if exc.status != 404:
                raise


def _leaf_fingerprint(pem_or_der: bytes) -> str | None:
    """Hash the SubjectPublicKeyInfo of the first cert found in ``pem_or_der``.

    The k8s secret may store PEM (fullchain) or DER. Either way we want
    the SHA-256 of the leaf DER encoding so it matches ``CertBundle.fingerprint_sha256``.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        if pem_or_der.lstrip().startswith(b"-----BEGIN"):
            certs = x509.load_pem_x509_certificates(pem_or_der)
            if not certs:
                return None
            cert = certs[0]
        else:
            cert = x509.load_der_x509_certificate(pem_or_der)
    except ValueError:
        return None
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()
