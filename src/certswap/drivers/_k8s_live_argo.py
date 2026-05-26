"""Live-kubernetes-client implementation of the ArgoCD-side methods.

Imported as a mixin into :class:`LiveK8sClient` so the Argo logic and
the base k8s logic can each fit under the 200-line file cap.
"""

from __future__ import annotations

from typing import Any

from kubernetes.client import ApiException

from certswap.drivers._k8s_client import ArgoApplicationView

ARGO_GROUP = "argoproj.io"
ARGO_VERSION = "v1alpha1"
ARGO_PLURAL = "applications"


class ArgoMixin:
    """Concrete argoproj.io/v1alpha1 Application methods.

    Subclassed by ``LiveK8sClient``, which provides ``self._cust`` (a
    ``CustomObjectsApi`` instance).
    """

    # ``_cust`` is a ``kubernetes.client.CustomObjectsApi`` provided by
    # the concrete subclass (LiveK8sClient). Typed as ``Any`` because the
    # kubernetes package ships no type stubs and ``disallow_any_unimported``
    # would otherwise refuse the real type.
    _cust: Any

    def get_argo_application(
        self, namespace: str, name: str
    ) -> ArgoApplicationView | None:
        try:
            obj = self._cust.get_namespaced_custom_object(
                group=ARGO_GROUP,
                version=ARGO_VERSION,
                namespace=namespace,
                plural=ARGO_PLURAL,
                name=name,
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise
        spec = obj.get("spec") or {}
        automated = (spec.get("syncPolicy") or {}).get("automated") or {}
        return ArgoApplicationView(
            name=name,
            namespace=namespace,
            automated_sync=bool(automated),
            self_heal=bool(automated.get("selfHeal", False)),
            sync_options=tuple((spec.get("syncPolicy") or {}).get("syncOptions") or []),
            ignore_differences_count=len(spec.get("ignoreDifferences") or []),
        )

    def disable_argo_automated_sync(self, namespace: str, name: str) -> None:
        self._patch_argo(namespace, name, {"spec": {"syncPolicy": {"automated": None}}})

    def re_enable_argo_sync_no_selfheal(self, namespace: str, name: str) -> None:
        self._patch_argo(
            namespace,
            name,
            {"spec": {"syncPolicy": {"automated": {"prune": True, "selfHeal": False}}}},
        )

    def set_argo_respect_ignore_differences(
        self,
        namespace: str,
        name: str,
        target_secret: str,
        target_ingress: str | None,
    ) -> None:
        current = self._cust.get_namespaced_custom_object(
            group=ARGO_GROUP,
            version=ARGO_VERSION,
            namespace=namespace,
            plural=ARGO_PLURAL,
            name=name,
        )
        spec = current.get("spec") or {}
        sync_options = list((spec.get("syncPolicy") or {}).get("syncOptions") or [])
        if "RespectIgnoreDifferences=true" not in sync_options:
            sync_options.append("RespectIgnoreDifferences=true")

        ignore_diffs = list(spec.get("ignoreDifferences") or [])
        ignore_diffs.append(
            {"group": "", "kind": "Secret", "name": target_secret, "jsonPointers": ["/data"]}
        )
        if target_ingress is not None:
            ignore_diffs.append(
                {
                    "group": "networking.k8s.io",
                    "kind": "Ingress",
                    "name": target_ingress,
                    "jsonPointers": ["/metadata/annotations"],
                }
            )
        self._patch_argo(
            namespace,
            name,
            {
                "spec": {
                    "syncPolicy": {"syncOptions": sync_options},
                    "ignoreDifferences": ignore_diffs,
                }
            },
        )

    def _patch_argo(self, namespace: str, name: str, body: dict[str, Any]) -> None:
        self._cust.patch_namespaced_custom_object(
            group=ARGO_GROUP,
            version=ARGO_VERSION,
            namespace=namespace,
            plural=ARGO_PLURAL,
            name=name,
            body=body,
        )
