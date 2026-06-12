"""Verify helpers for the k8s driver."""

from __future__ import annotations

from certswap.drivers import _k8s_argo
from certswap.drivers._k8s_client import K8sClient
from certswap.drivers._k8s_options import K8sOptions
from certswap.drivers.base import CheckResult, VerifyResult


def build_verify_result(
    client: K8sClient, opts: K8sOptions, *, expected_fingerprint: str | None
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
            checks.append(CheckResult(name=f"ingress {opts.ingress} present", ok=False))
            all_ok = False
        else:
            if opts.ingress_host:
                host_ok = opts.ingress_host in ingress.hosts
                checks.append(
                    CheckResult(
                        name=f"ingress serves host {opts.ingress_host}",
                        ok=host_ok,
                        detail=None if host_ok else f"hosts on ingress: {ingress.hosts}",
                    )
                )
                all_ok = all_ok and host_ok
            if not opts.keep_cert_manager:
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

    if not opts.keep_cert_manager:
        cert = client.find_certificate_for_secret(opts.namespace, opts.secret)
        cert_gone = cert is None
        checks.append(
            CheckResult(
                name="cert-manager Certificate not re-created",
                ok=cert_gone,
                detail=None if cert_gone else f"Certificate back: {cert.name if cert else ''}",
            )
        )
        all_ok = all_ok and cert_gone

    for chk in _k8s_argo.verify_checks(opts, client):
        checks.append(chk)
        all_ok = all_ok and chk.ok
    return VerifyResult(ok=all_ok, checks=checks)
