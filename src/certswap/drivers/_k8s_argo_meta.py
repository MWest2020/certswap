"""Pure helpers for the ArgoCD client layer (no kubernetes imports)."""

from __future__ import annotations

from typing import Any

# Argo's default tracking label/annotation: present on an Application CR
# that is itself deployed by another Argo app (app-of-apps).
TRACKING_LABEL = "app.kubernetes.io/instance"
TRACKING_ANNOTATION = "argocd.argoproj.io/tracking-id"


def detect_managed_by(metadata: dict[str, Any]) -> str | None:
    """Name the controller that owns this Application, if any."""
    for ref in metadata.get("ownerReferences") or []:
        if ref.get("kind") == "ApplicationSet":
            return f"ApplicationSet {ref.get('name')}"
    annotations = metadata.get("annotations") or {}
    if TRACKING_ANNOTATION in annotations:
        return f"Argo app-of-apps (tracking-id {annotations[TRACKING_ANNOTATION]!r})"
    labels = metadata.get("labels") or {}
    if TRACKING_LABEL in labels:
        return f"Argo app-of-apps (instance label {labels[TRACKING_LABEL]!r})"
    return None


def merge_ignore_entry(entries: list[dict[str, Any]], new: dict[str, Any]) -> None:
    """Merge ``new`` into ``entries``, deduped by (group, kind, name).

    An existing entry for the same resource gets the union of
    jsonPointers; otherwise the entry is appended. Keeps repeated swaps
    idempotent.
    """
    for entry in entries:
        if (entry.get("group"), entry.get("kind"), entry.get("name")) == (
            new.get("group"),
            new.get("kind"),
            new.get("name"),
        ):
            merged = list(
                dict.fromkeys((entry.get("jsonPointers") or []) + new["jsonPointers"])
            )
            entry["jsonPointers"] = merged
            return
    entries.append(new)
