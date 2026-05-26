from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from certswap.drivers._k8s_client import (
    CertificateView,
    IngressView,
    K8sClient,
    SecretView,
)
from certswap.drivers.base import TargetContext
from certswap.drivers.k8s import K8sDriver
from certswap.ingest.pem import parse_pem


@dataclass
class FakeK8s(K8sClient):
    context_name: str = "test-context"
    namespaces: set[str] = field(default_factory=lambda: {"default", "homelab"})
    secrets: dict[tuple[str, str], SecretView] = field(default_factory=dict)
    ingresses: dict[tuple[str, str], IngressView] = field(default_factory=dict)
    certificates: dict[tuple[str, str], CertificateView] = field(default_factory=dict)
    # Records of mutations:
    deleted_secrets: list[tuple[str, str]] = field(default_factory=list)
    created_secrets: list[tuple[str, str, bytes, bytes]] = field(default_factory=list)
    stripped_annotations: list[tuple[str, str]] = field(default_factory=list)
    deleted_certificates: list[tuple[str, str]] = field(default_factory=list)
    # After create, this fingerprint is reported by get_secret:
    next_created_fingerprint: str | None = None
    # Force errors on a named operation:
    raise_on: set[str] = field(default_factory=set)

    def current_context(self) -> str:
        return self.context_name

    def namespace_exists(self, namespace: str) -> bool:
        return namespace in self.namespaces

    def get_secret(self, namespace: str, name: str) -> SecretView | None:
        return self.secrets.get((namespace, name))

    def delete_secret(self, namespace: str, name: str) -> None:
        if "delete_secret" in self.raise_on:
            raise RuntimeError("forced delete_secret failure")
        self.deleted_secrets.append((namespace, name))
        self.secrets.pop((namespace, name), None)

    def create_tls_secret(
        self, namespace: str, name: str, cert_pem: bytes, key_pem: bytes
    ) -> None:
        if "create_tls_secret" in self.raise_on:
            raise RuntimeError("forced create_tls_secret failure")
        self.created_secrets.append((namespace, name, cert_pem, key_pem))
        self.secrets[(namespace, name)] = SecretView(
            name=name,
            namespace=namespace,
            type="kubernetes.io/tls",
            fingerprint_sha256=self.next_created_fingerprint,
        )

    def get_ingress(self, namespace: str, name: str) -> IngressView | None:
        return self.ingresses.get((namespace, name))

    def strip_ingress_cert_manager_annotation(self, namespace: str, name: str) -> bool:
        self.stripped_annotations.append((namespace, name))
        existing = self.ingresses.get((namespace, name))
        if existing is None:
            return False
        self.ingresses[(namespace, name)] = IngressView(
            name=existing.name,
            namespace=existing.namespace,
            hosts=existing.hosts,
            cert_manager_annotation=None,
        )
        return True

    def find_certificate_for_secret(
        self, namespace: str, secret_name: str
    ) -> CertificateView | None:
        for (ns, _name), cert in self.certificates.items():
            if ns == namespace and self._cert_targets_secret(cert, secret_name):
                return cert
        return None

    def _cert_targets_secret(self, cert: CertificateView, _name: str) -> bool:
        return True  # tests stage Certificates only when they should match

    def delete_certificate(self, namespace: str, name: str) -> None:
        self.deleted_certificates.append((namespace, name))
        for key in list(self.certificates):
            if key[0] == namespace and self.certificates[key].name == name:
                self.certificates.pop(key)


def _ctx(**opts: Any) -> TargetContext:
    base: dict[str, Any] = {"namespace": "homelab", "secret": "tls-cert"}
    base.update(opts)
    return TargetContext(driver="k8s", identifier=f"{base['namespace']}/{base['secret']}", options=base)


def test_plan_blocks_on_unknown_namespace(pem_bundle: Path) -> None:
    fake = FakeK8s(namespaces=set())
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx())
    assert plan.is_blocked
    assert any("namespace" in b for b in plan.blockers)


def test_plan_blocks_on_context_mismatch(pem_bundle: Path) -> None:
    fake = FakeK8s(context_name="real-context")
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(context="expected-context"))
    assert plan.is_blocked
    assert any("expected" in b and "got" in b for b in plan.blockers)


def test_plan_lists_secret_certificate_and_ingress_steps(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.certificates[("homelab", "tls-cert-cert")] = CertificateView(
        name="tls-cert-cert", namespace="homelab", issuer_ref="le-staging"
    )
    fake.ingresses[("homelab", "app")] = IngressView(
        name="app",
        namespace="homelab",
        hosts=["test.certswap.example"],
        cert_manager_annotation="le-staging",
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(ingress="app"))
    descs = [s.description for s in plan.steps]
    assert any("strip Ingress annotation" in d for d in descs)
    assert any("delete cert-manager Certificate" in d for d in descs)
    assert any("replace secret" in d for d in descs)
    assert plan.blockers == []


def test_plan_blocks_on_host_mismatch_without_override(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.ingresses[("homelab", "app")] = IngressView(
        name="app",
        namespace="homelab",
        hosts=["something.else.example"],
        cert_manager_annotation=None,
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(ingress="app"))
    assert plan.is_blocked
    assert any("not covered by leaf SANs" in b for b in plan.blockers)


def test_plan_allows_host_mismatch_when_flag_set(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.ingresses[("homelab", "app")] = IngressView(
        name="app",
        namespace="homelab",
        hosts=["something.else.example"],
        cert_manager_annotation=None,
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(ingress="app", allow_host_mismatch=True))
    assert plan.blockers == []


def test_apply_strips_annotation_deletes_certificate_and_recreates_secret(
    pem_bundle: Path,
) -> None:
    fake = FakeK8s()
    fake.certificates[("homelab", "x")] = CertificateView(
        name="tls-cert-cert", namespace="homelab", issuer_ref="le"
    )
    fake.ingresses[("homelab", "app")] = IngressView(
        name="app",
        namespace="homelab",
        hosts=["test.certswap.example"],
        cert_manager_annotation="le",
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    fake.next_created_fingerprint = cb.fingerprint_sha256()

    result = driver.apply(cb, _ctx(ingress="app"))
    assert result.exit_code == 0, result.model_dump()
    assert fake.stripped_annotations == [("homelab", "app")]
    assert fake.deleted_certificates == [("homelab", "tls-cert-cert")]
    assert fake.deleted_secrets == [("homelab", "tls-cert")]
    assert len(fake.created_secrets) == 1
    assert fake.created_secrets[0][:2] == ("homelab", "tls-cert")


def test_apply_records_step_failure_with_exit_50(pem_bundle: Path) -> None:
    fake = FakeK8s(raise_on={"create_tls_secret"})
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    result = driver.apply(cb, _ctx())
    assert result.exit_code == 50
    bad = [s for s in result.steps if not s.ok]
    assert any("create secret" in s.description for s in bad)


def test_apply_verify_detects_fingerprint_mismatch(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.next_created_fingerprint = "0" * 64  # deliberately wrong
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    result = driver.apply(cb, _ctx())
    assert result.exit_code == 60
    assert result.verify is not None
    mismatches = [c for c in result.verify.checks if not c.ok]
    assert any("matches bundle fingerprint" in c.name for c in mismatches)


def test_verify_returns_ok_when_secret_present(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.secrets[("homelab", "tls-cert")] = SecretView(
        name="tls-cert", namespace="homelab", type="kubernetes.io/tls", fingerprint_sha256="abc"
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    result = driver.verify(_ctx())
    assert result.ok is True


def test_verify_fails_when_secret_missing() -> None:
    fake = FakeK8s()
    driver = K8sDriver(client_factory=lambda _c: fake)
    result = driver.verify(_ctx())
    assert result.ok is False
    assert any("secret missing" in (c.detail or "") for c in result.checks)


def test_keep_cert_manager_warns_but_leaves_certificate(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.certificates[("homelab", "x")] = CertificateView(
        name="tls-cert-cert", namespace="homelab", issuer_ref="le"
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(keep_cert_manager=True))
    assert plan.blockers == []
    assert any("keep-cert-manager" in w for w in plan.warnings)
    # The "delete Certificate" step should NOT be present
    assert not any("delete cert-manager Certificate" in s.description for s in plan.steps)


@pytest.fixture
def k8s_driver_factory() -> tuple[FakeK8s, K8sDriver]:
    fake = FakeK8s()
    driver = K8sDriver(client_factory=lambda _c: fake)
    return fake, driver
