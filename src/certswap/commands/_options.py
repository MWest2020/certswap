"""Builders that turn CLI flags into driver-ready ``TargetContext.options`` dicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_local_options(
    dest: Path,
    cert_name: str,
    combined: bool,
    force: bool,
) -> dict[str, Any]:
    return {
        "dest": str(dest),
        "cert_name": cert_name,
        "combined": combined,
        "force": force,
    }


def build_k8s_options(
    namespace: str,
    secret: str,
    context: str | None,
    ingress: str | None,
    keep_cert_manager: bool,
    allow_host_mismatch: bool,
    ingress_host: str | None = None,
    argocd_app: str | None = None,
    argocd_namespace: str = "argocd",
    argocd_wait_seconds: float | None = None,
    argocd_force_managed: bool = False,
) -> dict[str, Any]:
    return {
        "namespace": namespace,
        "secret": secret,
        "context": context,
        "ingress": ingress,
        "ingress_host": ingress_host,
        "keep_cert_manager": keep_cert_manager,
        "allow_host_mismatch": allow_host_mismatch,
        "argocd_app": argocd_app,
        "argocd_namespace": argocd_namespace,
        "argocd_wait_seconds": argocd_wait_seconds,
        "argocd_force_managed": argocd_force_managed,
    }


def build_ssh_options(
    host: str,
    cert_dest: str | None,
    key_dest: str | None,
    chain_dest: str | None,
    combined_dest: str | None,
    mode_cert: int,
    mode_key: int,
    owner: str | None,
    group: str | None,
    reload_cmd: str | None,
    pre_check_cmd: str | None,
    post_check_cmd: str | None,
) -> dict[str, Any]:
    return {
        "host": host,
        "cert_dest": cert_dest,
        "key_dest": key_dest,
        "chain_dest": chain_dest,
        "combined_dest": combined_dest,
        "mode_cert": mode_cert,
        "mode_key": mode_key,
        "owner": owner,
        "group": group,
        "reload_cmd": reload_cmd,
        "pre_check_cmd": pre_check_cmd,
        "post_check_cmd": post_check_cmd,
    }
