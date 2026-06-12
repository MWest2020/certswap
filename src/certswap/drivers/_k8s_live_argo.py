"""Live-kubernetes-client implementation of the ArgoCD-side methods.

Imported as a mixin into :class:`LiveK8sClient` so the Argo logic and
the base k8s logic can each fit under the 200-line file cap.
"""

from __future__ import annotations

import json
from typing import Any

from kubernetes.client import ApiException

from certswap.drivers._k8s_argo_meta import detect_managed_by, merge_ignore_entry
from certswap.drivers._k8s_client import ArgoApplicationView

ARGO_GROUP = "argoproj.io"
ARGO_VERSION = "v1alpha1"
ARGO_PLURAL = "applications"

# The pre-swap spec.syncPolicy.automated value, JSON-encoded ("null" when
# the app was not auto-syncing). Stored on the Application itself so a
# crashed swap can still be restored from cluster state alone.
SAVED_SYNC_ANNOTATION = "certswap.io/saved-automated-sync"


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

    def _get_argo_raw(self, namespace: str, name: str) -> dict[str, Any] | None:
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
        return dict(obj)

    def get_argo_application(
        self, namespace: str, name: str
    ) -> ArgoApplicationView | None:
        obj = self._get_argo_raw(namespace, name)
        if obj is None:
            return None
        spec = obj.get("spec") or {}
        automated = (spec.get("syncPolicy") or {}).get("automated") or {}
        return ArgoApplicationView(
            name=name,
            namespace=namespace,
            automated_sync=bool(automated),
            self_heal=bool(automated.get("selfHeal", False)),
            sync_options=tuple((spec.get("syncPolicy") or {}).get("syncOptions") or []),
            ignore_differences_count=len(spec.get("ignoreDifferences") or []),
            managed_by=detect_managed_by(obj.get("metadata") or {}),
        )

    def disable_argo_automated_sync(self, namespace: str, name: str) -> None:
        """Disable auto-sync, saving the current policy in an annotation.

        An earlier saved annotation (crashed swap) is left untouched so
        the oldest known-good policy wins on restore.
        """
        obj = self._get_argo_raw(namespace, name)
        if obj is None:
            raise RuntimeError(f"argocd Application {namespace}/{name} not found")
        annotations = (obj.get("metadata") or {}).get("annotations") or {}
        body: dict[str, Any] = {"spec": {"syncPolicy": {"automated": None}}}
        if SAVED_SYNC_ANNOTATION not in annotations:
            automated = ((obj.get("spec") or {}).get("syncPolicy") or {}).get("automated")
            body["metadata"] = {
                "annotations": {SAVED_SYNC_ANNOTATION: json.dumps(automated)}
            }
        self._patch_argo(namespace, name, body)

    def restore_argo_sync(self, namespace: str, name: str) -> None:
        """Restore the saved sync policy, forcing ``selfHeal=false``.

        ``selfHeal`` stays off because Argo applies it without consulting
        ``ignoreDifferences`` — re-enabling it would revert the swap. An
        app that was not auto-syncing before stays that way.
        """
        obj = self._get_argo_raw(namespace, name)
        if obj is None:
            raise RuntimeError(f"argocd Application {namespace}/{name} not found")
        annotations = (obj.get("metadata") or {}).get("annotations") or {}
        raw = annotations.get(SAVED_SYNC_ANNOTATION)
        if raw is None:
            return  # nothing was saved; leave the Application as-is
        saved = json.loads(raw)
        automated = None if saved is None else {**saved, "selfHeal": False}
        self._patch_argo(
            namespace,
            name,
            {
                "metadata": {"annotations": {SAVED_SYNC_ANNOTATION: None}},
                "spec": {"syncPolicy": {"automated": automated}},
            },
        )

    def set_argo_respect_ignore_differences(
        self,
        namespace: str,
        name: str,
        target_secret: str,
        target_ingress: str | None,
        ingress_spec: bool = False,
    ) -> None:
        obj = self._get_argo_raw(namespace, name)
        if obj is None:
            raise RuntimeError(f"argocd Application {namespace}/{name} not found")
        spec = obj.get("spec") or {}
        sync_options = list((spec.get("syncPolicy") or {}).get("syncOptions") or [])
        if "RespectIgnoreDifferences=true" not in sync_options:
            sync_options.append("RespectIgnoreDifferences=true")

        ignore_diffs = list(spec.get("ignoreDifferences") or [])
        wanted: list[dict[str, Any]] = [
            {"group": "", "kind": "Secret", "name": target_secret, "jsonPointers": ["/data"]}
        ]
        if target_ingress is not None:
            pointers = ["/metadata/annotations"]
            if ingress_spec:
                # The swap added a host/TLS entry to the ingress spec;
                # protect it from being synced away. NOTE: chart-side
                # ingress changes stop propagating until this entry is
                # removed again.
                pointers.append("/spec")
            wanted.append(
                {
                    "group": "networking.k8s.io",
                    "kind": "Ingress",
                    "name": target_ingress,
                    "jsonPointers": pointers,
                }
            )
        for entry in wanted:
            merge_ignore_entry(ignore_diffs, entry)
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
