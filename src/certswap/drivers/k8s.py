"""K8s-secret driver: write a kubernetes.io/tls Secret atomically.

Removes the cert-manager Certificate that previously produced the
secret and strips the ``cert-manager.io/cluster-issuer`` annotation
from an Ingress (when supplied) so subsequent reconciliation does not
overwrite the manual swap.

ArgoCD coordination lives in :mod:`certswap.drivers._k8s_argo`.
"""

from __future__ import annotations

from collections.abc import Callable

from certswap.drivers import _k8s_argo, _k8s_ingress
from certswap.drivers._k8s_apply import record_step as _step
from certswap.drivers._k8s_client import (
    ClusterContextMismatch,
    K8sClient,
    load,
    verify_context,
)
from certswap.drivers._k8s_options import K8sOptions
from certswap.drivers._k8s_verify import build_verify_result
from certswap.drivers.base import (
    ApplyResult,
    Plan,
    PlanStep,
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
                would_do="replace kubernetes.io/tls secret in place (create if absent)",
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

        if opts.ingress and not _k8s_ingress.annotate_plan(plan, bundle, opts, client):
            return plan
        if not _k8s_argo.annotate_plan(plan, opts, client):
            return plan
        return plan

    def apply(self, bundle: CertBundle, ctx: TargetContext) -> ApplyResult:
        opts = K8sOptions.from_context(ctx)
        result = ApplyResult(driver=self.name, identifier=ctx.identifier)
        client = self._factory(opts.context)
        if opts.context:
            verify_context(client, opts.context)

        _k8s_argo.apply_pre(result, opts, client, record_step=_step)

        if opts.ingress and opts.ingress_host:
            _step(
                result,
                f"add host {opts.ingress_host} to ingress {opts.ingress}",
                lambda: client.ensure_ingress_host(
                    opts.namespace, opts.ingress or "", opts.ingress_host or "", opts.secret
                ),
            )

        if opts.ingress and not opts.keep_cert_manager:
            _step(
                result,
                f"strip ingress annotation on {opts.ingress}",
                lambda: client.strip_ingress_cert_manager_annotation(
                    opts.namespace, opts.ingress or ""
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
            f"replace secret {opts.secret}",
            lambda: client.put_tls_secret(
                opts.namespace, opts.secret, bundle.to_pem_fullchain(), bundle.to_pem_key()
            ),
        )

        _k8s_argo.apply_post(result, opts, client, record_step=_step)

        if any(not s.ok for s in result.steps):
            result.exit_code = 50
            return result
        result.verify = build_verify_result(
            client, opts, expected_fingerprint=bundle.fingerprint_sha256()
        )
        if not result.verify.ok:
            result.exit_code = 60
        return result

    def verify(self, ctx: TargetContext) -> VerifyResult:
        opts = K8sOptions.from_context(ctx)
        client = self._factory(opts.context)
        return build_verify_result(client, opts, expected_fingerprint=None)


def _describe_secret(secret: object) -> str | None:
    if secret is None:
        return None
    return f"type={getattr(secret, 'type', '?')} fp={getattr(secret, 'fingerprint_sha256', '?')}"


register(K8sDriver())

__all__ = ["K8sDriver"]
