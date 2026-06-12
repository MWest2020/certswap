from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from certswap.drivers._k8s_client import (
    ArgoApplicationView,
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
    argo_apps: dict[tuple[str, str], ArgoApplicationView] = field(default_factory=dict)
    # Records of mutations:
    put_secrets: list[tuple[str, str, bytes, bytes]] = field(default_factory=list)
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

    def put_tls_secret(
        self, namespace: str, name: str, cert_pem: bytes, key_pem: bytes
    ) -> None:
        if "put_tls_secret" in self.raise_on:
            raise RuntimeError("forced put_tls_secret failure")
        self.put_secrets.append((namespace, name, cert_pem, key_pem))
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

    # ArgoCD ---------------------------------------------------------------

    argo_disabled: list[tuple[str, str]] = field(default_factory=list)
    argo_respected: list[tuple[str, str, str, str | None]] = field(default_factory=list)
    argo_restored: list[tuple[str, str]] = field(default_factory=list)

    def get_argo_application(
        self, namespace: str, name: str
    ) -> ArgoApplicationView | None:
        return self.argo_apps.get((namespace, name))

    def disable_argo_automated_sync(self, namespace: str, name: str) -> None:
        self.argo_disabled.append((namespace, name))
        existing = self.argo_apps.get((namespace, name))
        if existing is not None:
            self.argo_apps[(namespace, name)] = ArgoApplicationView(
                name=existing.name,
                namespace=existing.namespace,
                automated_sync=False,
                self_heal=False,
                sync_options=existing.sync_options,
                ignore_differences_count=existing.ignore_differences_count,
            )

    def restore_argo_sync(self, namespace: str, name: str) -> None:
        self.argo_restored.append((namespace, name))
        existing = self.argo_apps.get((namespace, name))
        if existing is not None:
            self.argo_apps[(namespace, name)] = ArgoApplicationView(
                name=existing.name,
                namespace=existing.namespace,
                automated_sync=True,
                self_heal=False,
                sync_options=existing.sync_options,
                ignore_differences_count=existing.ignore_differences_count,
            )

    def set_argo_respect_ignore_differences(
        self,
        namespace: str,
        name: str,
        target_secret: str,
        target_ingress: str | None,
    ) -> None:
        self.argo_respected.append((namespace, name, target_secret, target_ingress))
        existing = self.argo_apps.get((namespace, name))
        if existing is not None:
            opts = (*existing.sync_options, "RespectIgnoreDifferences=true")
            self.argo_apps[(namespace, name)] = ArgoApplicationView(
                name=existing.name,
                namespace=existing.namespace,
                automated_sync=existing.automated_sync,
                self_heal=existing.self_heal,
                sync_options=opts,
                ignore_differences_count=existing.ignore_differences_count + 1,
            )


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
    assert len(fake.put_secrets) == 1
    assert fake.put_secrets[0][:2] == ("homelab", "tls-cert")


def test_apply_records_step_failure_with_exit_50(pem_bundle: Path) -> None:
    fake = FakeK8s(raise_on={"put_tls_secret"})
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    result = driver.apply(cb, _ctx())
    assert result.exit_code == 50
    bad = [s for s in result.steps if not s.ok]
    assert any("replace secret" in s.description for s in bad)


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


# -------- ArgoCD layer tests (M4b) --------


def _argo_app(automated: bool = True, self_heal: bool = True) -> ArgoApplicationView:
    return ArgoApplicationView(
        name="my-app",
        namespace="argocd",
        automated_sync=automated,
        self_heal=self_heal,
        sync_options=(),
        ignore_differences_count=0,
    )


def test_argo_plan_blocks_when_application_missing(pem_bundle: Path) -> None:
    fake = FakeK8s()
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(argocd_app="missing"))
    assert plan.is_blocked
    assert any("argocd Application" in b for b in plan.blockers)


def test_argo_plan_reports_pre_and_post_steps(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.argo_apps[("argocd", "my-app")] = _argo_app()
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(argocd_app="my-app"))
    descs = [s.description for s in plan.steps]
    assert any("disable automated sync" in d for d in descs)
    assert any("restore automated sync" in d for d in descs)


def test_argo_apply_orders_disable_then_changes_then_reenable(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.argo_apps[("argocd", "my-app")] = _argo_app()
    fake.ingresses[("homelab", "app")] = IngressView(
        name="app",
        namespace="homelab",
        hosts=["test.certswap.example"],
        cert_manager_annotation="le",
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    fake.next_created_fingerprint = cb.fingerprint_sha256()

    result = driver.apply(
        cb,
        _ctx(argocd_app="my-app", ingress="app", argocd_wait_seconds=0),
    )
    assert result.exit_code == 0, result.model_dump()
    # Argo disable must come BEFORE the ingress strip
    descs = [s.description for s in result.steps]
    disable_idx = next(i for i, d in enumerate(descs) if "disable automated sync" in d)
    strip_idx = next(i for i, d in enumerate(descs) if "strip ingress annotation" in d)
    replace_idx = next(i for i, d in enumerate(descs) if "replace secret" in d)
    restore_idx = next(i for i, d in enumerate(descs) if "restore automated sync" in d)
    assert disable_idx < strip_idx < replace_idx < restore_idx
    assert fake.argo_disabled == [("argocd", "my-app")]
    assert len(fake.argo_respected) == 1
    assert fake.argo_respected[0][2] == "tls-cert"  # target_secret
    assert fake.argo_respected[0][3] == "app"  # target_ingress
    assert fake.argo_restored == [("argocd", "my-app")]


def test_argo_apply_skips_wait_when_zero(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.argo_apps[("argocd", "my-app")] = _argo_app()
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    fake.next_created_fingerprint = cb.fingerprint_sha256()
    # Setting argocd_wait_seconds=0 must short-circuit the time.sleep call;
    # if it didn't, this test would still pass but in 60s instead of <1s.
    import time

    started = time.perf_counter()
    result = driver.apply(
        cb, _ctx(argocd_app="my-app", argocd_wait_seconds=0)
    )
    elapsed = time.perf_counter() - started
    assert result.exit_code == 0
    assert elapsed < 5.0


def test_argo_plan_blocks_when_application_is_managed(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.argo_apps[("argocd", "my-app")] = ArgoApplicationView(
        name="my-app",
        namespace="argocd",
        automated_sync=True,
        self_heal=True,
        sync_options=(),
        ignore_differences_count=0,
        managed_by="ApplicationSet my-set",
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(argocd_app="my-app"))
    assert plan.is_blocked
    assert any("ApplicationSet my-set" in b for b in plan.blockers)
    assert any("--argocd-force-managed" in b for b in plan.blockers)


def test_argo_plan_allows_managed_application_with_force_flag(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.argo_apps[("argocd", "my-app")] = ArgoApplicationView(
        name="my-app",
        namespace="argocd",
        automated_sync=True,
        self_heal=True,
        sync_options=(),
        ignore_differences_count=0,
        managed_by="ApplicationSet my-set",
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    cb = parse_pem(pem_bundle)
    plan = driver.plan(cb, _ctx(argocd_app="my-app", argocd_force_managed=True))
    assert plan.blockers == []
    assert any("revert" in w for w in plan.warnings)


def test_argo_verify_fails_if_selfheal_back_on(pem_bundle: Path) -> None:
    fake = FakeK8s()
    fake.argo_apps[("argocd", "my-app")] = _argo_app(self_heal=True)
    fake.secrets[("homelab", "tls-cert")] = SecretView(
        name="tls-cert",
        namespace="homelab",
        type="kubernetes.io/tls",
        fingerprint_sha256=None,
    )
    driver = K8sDriver(client_factory=lambda _c: fake)
    result = driver.verify(_ctx(argocd_app="my-app"))
    assert result.ok is False
    bad = [c for c in result.checks if not c.ok]
    assert any("selfHeal=false" in c.name for c in bad)
