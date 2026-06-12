"""Live-kubernetes-client implementation of the Ingress-side methods.

Imported as a mixin into :class:`LiveK8sClient` so the ingress logic and
the base k8s logic can each fit under the 200-line file cap.
"""

from __future__ import annotations

import copy
from typing import Any

from kubernetes.client import ApiException, V1IngressTLS

CERT_MANAGER_ANNOTATION = "cert-manager.io/cluster-issuer"
CERT_MANAGER_ANNOTATION_ISSUER = "cert-manager.io/issuer"


class IngressMixin:
    """Concrete networking.k8s.io/v1 Ingress methods.

    Subclassed by ``LiveK8sClient``, which provides ``self._net`` (a
    ``NetworkingV1Api`` instance). Typed as ``Any`` because the
    kubernetes package ships no type stubs.
    """

    _net: Any

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

    def ensure_ingress_host(
        self, namespace: str, name: str, host: str, secret_name: str
    ) -> bool:
        """Add ``host`` (rule + TLS entry) to an existing ingress, idempotently.

        The new rule copies the backend of the first existing rule. A TLS
        entry covering exactly this host gets its secretName corrected if
        it differs; otherwise a new entry is appended. Returns True when
        the ingress was modified.
        """
        obj = self._net.read_namespaced_ingress(name=name, namespace=namespace)
        changed = False

        rules = list(obj.spec.rules or [])
        if not any(r.host == host for r in rules):
            if not rules:
                raise RuntimeError(
                    f"ingress {namespace}/{name} has no rules to copy a backend from"
                )
            new_rule = copy.deepcopy(rules[0])
            new_rule.host = host
            rules.append(new_rule)
            obj.spec.rules = rules
            changed = True

        tls = list(obj.spec.tls or [])
        entry = next((t for t in tls if host in (t.hosts or [])), None)
        if entry is None:
            tls.append(V1IngressTLS(hosts=[host], secret_name=secret_name))
            obj.spec.tls = tls
            changed = True
        elif entry.secret_name != secret_name and list(entry.hosts or []) == [host]:
            entry.secret_name = secret_name
            obj.spec.tls = tls
            changed = True

        if changed:
            self._net.replace_namespaced_ingress(name=name, namespace=namespace, body=obj)
        return changed
