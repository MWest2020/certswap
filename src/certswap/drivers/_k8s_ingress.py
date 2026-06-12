"""Ingress planning for the k8s driver.

Covers the cert-manager interplay: stripping the per-ingress
``cluster-issuer`` annotation, and — with ``ingress_host`` — attaching a
new host whose certificate is swapped manually. The annotation and the
host addition cannot coexist: cert-manager's ingress-shim issues a
certificate for every TLS entry on an annotated ingress and would
overwrite the swapped secret.
"""

from __future__ import annotations

from certswap.core.validation import san_matches_host
from certswap.drivers._k8s_client import K8sClient
from certswap.drivers._k8s_options import K8sOptions
from certswap.drivers.base import Plan, PlanStep
from certswap.models import CertBundle


def annotate_plan(
    plan: Plan, bundle: CertBundle, opts: K8sOptions, client: K8sClient
) -> bool:
    """Add ingress steps to ``plan``. Returns False when blocked.

    Caller guarantees ``opts.ingress`` is set.
    """
    ingress_name = opts.ingress or ""
    ingress = client.get_ingress(opts.namespace, ingress_name)
    if ingress is None:
        plan.blockers.append(f"ingress {opts.namespace}/{ingress_name} not found")
        return False
    if opts.ingress_host and opts.keep_cert_manager:
        plan.blockers.append(
            "--ingress-host cannot be combined with --keep-cert-manager: "
            "cert-manager's ingress-shim would issue a certificate for the "
            "new TLS entry and overwrite the swapped secret"
        )
        return False
    # With --ingress-host only the new host must match the bundle; the
    # other hosts on a shared ingress keep their own TLS entries.
    hosts_to_check = [opts.ingress_host] if opts.ingress_host else ingress.hosts
    if not opts.allow_host_mismatch:
        mismatched = [h for h in hosts_to_check if not san_matches_host(bundle, h)]
        if mismatched:
            plan.blockers.append(
                f"ingress hosts {mismatched} not covered by leaf SANs "
                f"{bundle.sans()}; pass --allow-host-mismatch to override"
            )
            return False
    if opts.ingress_host:
        plan.steps.insert(
            0,
            PlanStep(
                description=f"add host {opts.ingress_host} to ingress {ingress.name}",
                before=f"hosts={ingress.hosts}",
                would_do=f"add rule + TLS entry (secret {opts.secret}), idempotent",
            ),
        )
    if ingress.cert_manager_annotation and not opts.keep_cert_manager:
        others = [h for h in ingress.hosts if h != opts.ingress_host]
        if opts.ingress_host and others:
            plan.warnings.append(
                f"stripping the cert-manager annotation stops automatic "
                f"renewal for the other hosts on this ingress: {others} — "
                "move them to a separate annotated ingress before their "
                "current certificates expire"
            )
        plan.steps.insert(
            0,
            PlanStep(
                description=f"strip Ingress annotation on {ingress.name}",
                before=f"cert-manager annotation={ingress.cert_manager_annotation}",
                would_do="remove cert-manager.io/cluster-issuer annotation",
            ),
        )
    return True
