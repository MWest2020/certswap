"""Proxmox VE driver: thin wrapper over the ssh driver with PVE defaults.

A Proxmox node serves its web UI from ``pveproxy``. The cert+chain go to
``/etc/pve/local/pveproxy-ssl.pem`` and the key to
``/etc/pve/local/pveproxy-ssl.key``; ``systemctl restart pveproxy``
applies them, and a curl probe at ``https://localhost:8006`` confirms
the swap took.

There is no PVE-specific protocol — every action is plain ssh against
a host that runs Proxmox. Anything you'd want to override (paths,
reload command) bubbles up via the same ``--*-dest`` / ``--reload``
flags that the ssh driver already exposes.
"""

from __future__ import annotations

from typing import Any

from certswap.drivers.base import (
    ApplyResult,
    Plan,
    TargetContext,
    VerifyResult,
    register,
)
from certswap.drivers.ssh import SshDriver
from certswap.models import CertBundle

PVE_CERT_PATH = "/etc/pve/local/pveproxy-ssl.pem"
PVE_KEY_PATH = "/etc/pve/local/pveproxy-ssl.key"
PVE_RELOAD = "systemctl restart pveproxy"
PVE_POST_CHECK = "curl -fsS -o /dev/null https://localhost:8006"


def _build_ssh_context(ctx: TargetContext) -> TargetContext:
    o: dict[str, Any] = ctx.options
    host = o.get("host")
    if not host:
        raise ValueError("proxmox driver requires `host` in TargetContext.options")
    overrides: dict[str, Any] = {
        "host": str(host),
        "cert_dest": o.get("cert_dest") or PVE_CERT_PATH,
        "key_dest": o.get("key_dest") or PVE_KEY_PATH,
        "chain_dest": o.get("chain_dest") or None,
        "combined_dest": o.get("combined_dest") or None,
        "mode_cert": o.get("mode_cert") or 0o644,
        # PVE expects the key readable by the www-data group. Operators
        # who use a different layout can override.
        "mode_key": o.get("mode_key") or 0o640,
        "owner": o.get("owner") or "root",
        "group": o.get("group") or "www-data",
        "reload_cmd": o.get("reload_cmd") or PVE_RELOAD,
        "pre_check_cmd": o.get("pre_check_cmd") or None,
        "post_check_cmd": o.get("post_check_cmd") or PVE_POST_CHECK,
    }
    return TargetContext(
        driver="ssh",
        identifier=f"{host}:pveproxy",
        options=overrides,
    )


class ProxmoxDriver:
    name: str = "proxmox"

    def __init__(self, ssh: SshDriver | None = None) -> None:
        self._ssh = ssh or SshDriver()

    def plan(self, bundle: CertBundle, ctx: TargetContext) -> Plan:
        ssh_ctx = _build_ssh_context(ctx)
        plan = self._ssh.plan(bundle, ssh_ctx)
        # Re-stamp the driver name so plan output and evidence reflect
        # the user-visible target, not the internal ssh delegate.
        plan.driver = self.name
        plan.identifier = ctx.identifier
        return plan

    def apply(self, bundle: CertBundle, ctx: TargetContext) -> ApplyResult:
        ssh_ctx = _build_ssh_context(ctx)
        result = self._ssh.apply(bundle, ssh_ctx)
        result.driver = self.name
        result.identifier = ctx.identifier
        return result

    def verify(self, ctx: TargetContext) -> VerifyResult:
        ssh_ctx = _build_ssh_context(ctx)
        return self._ssh.verify(ssh_ctx)


register(ProxmoxDriver())

__all__ = ["ProxmoxDriver"]
