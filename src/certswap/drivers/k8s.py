"""K8s-secret driver: write a kubernetes.io/tls Secret atomically.

Removes the cert-manager Certificate that previously produced the
secret and strips the ``cert-manager.io/cluster-issuer`` annotation
from an Ingress (when supplied) so subsequent reconciliation does not
overwrite the manual swap.

ArgoCD reconciliation handling lives in M4b on top of this driver.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from certswap.core.validation import san_matches_host
from certswap.drivers._k8s_client import ClusterContextMismatch, K8sClient, load, verify_context
from certswap.drivers._k8s_options import K8sOptions
from certswap.drivers.base import (
    ApplyResult,
    CheckResult,
    Plan,
    PlanStep,
    StepResult,
    TargetContext,
    VerifyResult,
    register,
)
from certswap.models import CertBundle

ClientFactory = Callable[[str | None], K8sClient]


class K8sDriver:
    name: str = "k8s"

    def __init__(self, client_factory: ClientFactory = load) -> None:
        self._factory = client_factory

    def plan(self, bundle: CertBundle, ctx: TargetContext) -> Plan:
        opts = K8sOptions.from_context(ctx)
        plan = Plan(driver=self.name, identifier=ctx.identifier)
        try:
            client = self._factory(opts.context)
        except Exception as exc:
            plan.blockers.append(f"k8s client setup failed: {exc}")
            return plan

        if opts.context:
            try:
                verify_context(client, opts.context)
            except ClusterContextMismatch as exc:
                plan.blockers.append(str(exc))
                return plan

        if not client.namespace_exists(opts.namespace):
            plan.blockers.append(f"namespace {opts.namespace!r} not found")
            return plan

        existing = client.get_secret(opts.namespace, opts.secret)
        plan.steps.append(
            PlanStep(
                description=f"replace secret {opts.namespace}/{opts.secret}",
                before=_describe_secret(existing),
                would_do="delete + create kubernetes.io/tls secret",
            )
        )

        certificate = client.find_certificate_for_secret(opts.namespace, opts.secret)
        if certificate is not None and not opts.keep_cert_manager:
            plan.steps.insert(
                0,
                PlanStep(
                    description=f"delete cert-manager Certificate {certificate.name}",
                    before=f"issuer={certificate.issuer_ref}",
                    would_do="delete certificates.cert-manager.io",
                ),
            )
        elif certificate is not None and opts.keep_cert_manager:
            plan.warnings.append(
                f"cert-manager Certificate {certificate.name} present but "
                "--keep-cert-manager set; it will overwrite this secret on reconcile"
            )

        if opts.ingress:
            ingress = client.get_ingress(opts.namespace, opts.ingress)
            if ingress is None:
                plan.blockers.append(f"ingress {opts.namespace}/{opts.ingress} not found")
                return plan
            if not opts.allow_host_mismatch:
                mismatched = [h for h in ingress.hosts if not san_matches_host(bundle, h)]
                if mismatched:
                    plan.blockers.append(
                        f"ingress hosts {mismatched} not covered by leaf SANs "
                        f"{bundle.sans()}; pass --allow-host-mismatch to override"
                    )
                    return plan
            if ingress.cert_manager_annotation and not opts.keep_cert_manager:
                plan.steps.insert(
                    0,
                    PlanStep(
                        description=f"strip Ingress annotation on {ingress.name}",
                        before=f"cert-manager annotation={ingress.cert_manager_annotation}",
                        would_do="remove cert-manager.io/cluster-issuer annotation",
                    ),
                )
        return plan

    def apply(self, bundle: CertBundle, ctx: TargetContext) -> ApplyResult:
        opts = K8sOptions.from_context(ctx)
        result = ApplyResult(driver=self.name, identifier=ctx.identifier)
        client = self._factory(opts.context)
        if opts.context:
            verify_context(client, opts.context)

        if opts.ingress and not opts.keep_cert_manager:
            _step(
                result,
                f"strip ingress annotation on {opts.ingress}",
                lambda: client.strip_ingress_cert_manager_annotation(
                    opts.namespace, opts.ingress  # type: ignore[arg-type]
                ),
            )

        if not opts.keep_cert_manager:
            cert = client.find_certificate_for_secret(opts.namespace, opts.secret)
            if cert is not None:
                _step(
                    result,
                    f"delete Certificate {cert.name}",
                    lambda: client.delete_certificate(opts.namespace, cert.name),
                )

        _step(
            result,
            f"delete secret {opts.secret}",
            lambda: client.delete_secret(opts.namespace, opts.secret),
        )
        _step(
            result,
            f"create secret {opts.secret}",
            lambda: client.create_tls_secret(
                opts.namespace, opts.secret, bundle.to_pem_fullchain(), bundle.to_pem_key()
            ),
        )

        if any(not s.ok for s in result.steps):
            result.exit_code = 50
            return result
        result.verify = self._verify_with_bundle(client, opts, bundle.fingerprint_sha256())
        if not result.verify.ok:
            result.exit_code = 60
        return result

    def verify(self, ctx: TargetContext) -> VerifyResult:
        opts = K8sOptions.from_context(ctx)
        client = self._factory(opts.context)
        return self._verify_with_bundle(client, opts, expected_fingerprint=None)

    def _verify_with_bundle(
        self, client: K8sClient, opts: K8sOptions, expected_fingerprint: str | None
    ) -> VerifyResult:
        checks: list[CheckResult] = []
        all_ok = True
        secret = client.get_secret(opts.namespace, opts.secret)
        secret_ok = secret is not None and secret.type == "kubernetes.io/tls"
        checks.append(
            CheckResult(
                name=f"secret {opts.namespace}/{opts.secret} is kubernetes.io/tls",
                ok=secret_ok,
                detail=None if secret_ok else "secret missing or wrong type",
            )
        )
        all_ok = all_ok and secret_ok

        if secret_ok and expected_fingerprint is not None:
            match = secret is not None and secret.fingerprint_sha256 == expected_fingerprint
            checks.append(
                CheckResult(
                    name="secret tls.crt matches bundle fingerprint",
                    ok=match,
                    detail=None
                    if match
                    else f"got {secret.fingerprint_sha256 if secret else None}",
                )
            )
            all_ok = all_ok and match

        if opts.ingress:
            ingress = client.get_ingress(opts.namespace, opts.ingress)
            if ingress is None:
                checks.append(
                    CheckResult(name=f"ingress {opts.ingress} present", ok=False)
                )
                all_ok = False
            elif not opts.keep_cert_manager:
                annot_ok = ingress.cert_manager_annotation is None
                checks.append(
                    CheckResult(
                        name="ingress free of cert-manager.io/cluster-issuer",
                        ok=annot_ok,
                        detail=None
                        if annot_ok
                        else f"annotation back: {ingress.cert_manager_annotation}",
                    )
                )
                all_ok = all_ok and annot_ok
        return VerifyResult(ok=all_ok, checks=checks)


def _describe_secret(secret: object) -> str | None:
    if secret is None:
        return None
    return f"type={getattr(secret, 'type', '?')} fp={getattr(secret, 'fingerprint_sha256', '?')}"


def _step(result: ApplyResult, description: str, action: Callable[[], object]) -> None:
    start = time.perf_counter()
    try:
        action()
        ok = True
        err: str | None = None
    except Exception as exc:
        ok = False
        err = str(exc)
    result.steps.append(
        StepResult(
            description=description,
            before=None,
            after=None,
            duration_ms=int((time.perf_counter() - start) * 1000),
            ok=ok,
            error=err,
        )
    )


register(K8sDriver())

__all__ = ["K8sDriver"]
