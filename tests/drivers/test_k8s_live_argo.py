"""Tests for the ArgoMixin merge-patch logic against a stub CustomObjectsApi.

The stub applies RFC 7386 JSON merge patch semantics (null deletes a key,
objects merge recursively, everything else replaces), matching what the
kubernetes client does for ``patch_namespaced_custom_object``.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from certswap.drivers._k8s_argo_meta import detect_managed_by
from certswap.drivers._k8s_live_argo import SAVED_SYNC_ANNOTATION, ArgoMixin


def _merge(target: dict[str, Any], patch: dict[str, Any]) -> None:
    for key, value in patch.items():
        if value is None:
            target.pop(key, None)
        elif isinstance(value, dict):
            node = target.setdefault(key, {})
            if isinstance(node, dict):
                _merge(node, value)
            else:
                target[key] = copy.deepcopy(value)
        else:
            target[key] = copy.deepcopy(value)


class StubCust:
    def __init__(self, obj: dict[str, Any]) -> None:
        self.obj = obj
        self.patch_count = 0

    def get_namespaced_custom_object(self, **_kw: Any) -> dict[str, Any]:
        return copy.deepcopy(self.obj)

    def patch_namespaced_custom_object(self, *, body: dict[str, Any], **_kw: Any) -> None:
        self.patch_count += 1
        _merge(self.obj, body)


class Client(ArgoMixin):
    def __init__(self, obj: dict[str, Any]) -> None:
        self._cust = StubCust(obj)


def _app(
    automated: dict[str, Any] | None,
    *,
    annotations: dict[str, str] | None = None,
) -> dict[str, Any]:
    sync_policy: dict[str, Any] = {}
    if automated is not None:
        sync_policy["automated"] = automated
    return {
        "metadata": {"annotations": dict(annotations or {})},
        "spec": {"syncPolicy": sync_policy},
    }


def test_disable_saves_original_policy_and_clears_automated() -> None:
    client = Client(_app({"prune": False, "selfHeal": True}))
    client.disable_argo_automated_sync("argocd", "my-app")
    obj = client._cust.obj
    assert "automated" not in obj["spec"]["syncPolicy"]
    saved = json.loads(obj["metadata"]["annotations"][SAVED_SYNC_ANNOTATION])
    assert saved == {"prune": False, "selfHeal": True}


def test_disable_keeps_earlier_saved_policy_from_crashed_swap() -> None:
    earlier = json.dumps({"prune": True})
    client = Client(_app(None, annotations={SAVED_SYNC_ANNOTATION: earlier}))
    client.disable_argo_automated_sync("argocd", "my-app")
    assert client._cust.obj["metadata"]["annotations"][SAVED_SYNC_ANNOTATION] == earlier


def test_restore_preserves_prune_and_forces_selfheal_off() -> None:
    client = Client(_app({"prune": False, "selfHeal": True}))
    client.disable_argo_automated_sync("argocd", "my-app")
    client.restore_argo_sync("argocd", "my-app")
    obj = client._cust.obj
    # prune stays exactly as it was — never hardcoded on.
    assert obj["spec"]["syncPolicy"]["automated"] == {"prune": False, "selfHeal": False}
    assert SAVED_SYNC_ANNOTATION not in obj["metadata"]["annotations"]


def test_restore_keeps_sync_off_for_app_that_was_not_automated() -> None:
    client = Client(_app(None))
    client.disable_argo_automated_sync("argocd", "my-app")
    client.restore_argo_sync("argocd", "my-app")
    obj = client._cust.obj
    assert "automated" not in obj["spec"]["syncPolicy"]
    assert SAVED_SYNC_ANNOTATION not in obj["metadata"]["annotations"]


def test_restore_without_saved_annotation_is_a_noop() -> None:
    client = Client(_app({"prune": True}))
    client.restore_argo_sync("argocd", "my-app")
    assert client._cust.patch_count == 0
    assert client._cust.obj["spec"]["syncPolicy"]["automated"] == {"prune": True}


def test_respect_ignore_differences_is_idempotent() -> None:
    client = Client(_app({"prune": True}))
    for _ in range(3):
        client.set_argo_respect_ignore_differences("argocd", "my-app", "tls-cert", "app")
    spec = client._cust.obj["spec"]
    assert spec["syncPolicy"]["syncOptions"] == ["RespectIgnoreDifferences=true"]
    assert len(spec["ignoreDifferences"]) == 2
    kinds = {e["kind"] for e in spec["ignoreDifferences"]}
    assert kinds == {"Secret", "Ingress"}


def test_respect_ignore_differences_preserves_existing_entries() -> None:
    obj = _app({"prune": True})
    obj["spec"]["ignoreDifferences"] = [
        {"group": "apps", "kind": "Deployment", "jsonPointers": ["/spec/replicas"]}
    ]
    obj["spec"]["syncPolicy"]["syncOptions"] = ["CreateNamespace=true"]
    client = Client(obj)
    client.set_argo_respect_ignore_differences("argocd", "my-app", "tls-cert", None)
    spec = client._cust.obj["spec"]
    assert spec["syncPolicy"]["syncOptions"] == [
        "CreateNamespace=true",
        "RespectIgnoreDifferences=true",
    ]
    assert len(spec["ignoreDifferences"]) == 2


def test_respect_ignore_differences_ingress_spec_pointer_merges() -> None:
    client = Client(_app({"prune": True}))
    # First a plain swap (annotations only), then one that touched the spec.
    client.set_argo_respect_ignore_differences("argocd", "my-app", "tls-cert", "app")
    client.set_argo_respect_ignore_differences(
        "argocd", "my-app", "tls-cert", "app", ingress_spec=True
    )
    spec = client._cust.obj["spec"]
    ingress_entries = [e for e in spec["ignoreDifferences"] if e["kind"] == "Ingress"]
    assert len(ingress_entries) == 1
    assert ingress_entries[0]["jsonPointers"] == ["/metadata/annotations", "/spec"]


def test_detect_managed_by_applicationset_owner() -> None:
    meta = {"ownerReferences": [{"kind": "ApplicationSet", "name": "my-set"}]}
    assert detect_managed_by(meta) == "ApplicationSet my-set"


def test_detect_managed_by_tracking_annotation() -> None:
    meta = {"annotations": {"argocd.argoproj.io/tracking-id": "root:apps/Application:argocd/my-app"}}
    result = detect_managed_by(meta)
    assert result is not None and "app-of-apps" in result


def test_detect_managed_by_instance_label() -> None:
    meta = {"labels": {"app.kubernetes.io/instance": "root-app"}}
    result = detect_managed_by(meta)
    assert result is not None and "root-app" in result


def test_detect_managed_by_none_for_standalone_app() -> None:
    assert detect_managed_by({"labels": {"team": "ops"}}) is None
