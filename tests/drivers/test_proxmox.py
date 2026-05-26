from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from certswap.drivers import get_driver
from certswap.drivers.base import TargetContext
from certswap.drivers.proxmox import (
    PVE_CERT_PATH,
    PVE_KEY_PATH,
    PVE_POST_CHECK,
    PVE_RELOAD,
)
from certswap.ingest.pem import parse_pem


def _make_completed(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _ctx(**opts: Any) -> TargetContext:
    base: dict[str, Any] = {"host": "pve-node"}
    base.update(opts)
    return TargetContext(
        driver="proxmox", identifier=f"{base['host']}:pveproxy", options=base
    )


@pytest.fixture
def patch_subprocess(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[list[str]]]:
    calls: list[list[str]] = []

    def installer(default_ok: bool = True) -> list[list[str]]:
        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            calls.append(list(argv))
            return _make_completed(0 if default_ok else 1)

        monkeypatch.setattr("certswap.drivers._ssh_shell.subprocess.run", fake_run)
        return calls

    return installer


def test_plan_uses_pve_defaults(
    pem_bundle: Path, patch_subprocess: Callable[..., list[list[str]]]
) -> None:
    calls = patch_subprocess(default_ok=True)
    cb = parse_pem(pem_bundle)
    plan = get_driver("proxmox").plan(cb, _ctx())
    descs = [s.description for s in plan.steps]
    assert any(PVE_CERT_PATH in d for d in descs)
    assert any(PVE_KEY_PATH in d for d in descs)
    assert any("reload service" == d for d in descs)
    assert any("post-check" == d for d in descs)
    # And the rendered driver name on the Plan stays user-visible:
    assert plan.driver == "proxmox"
    # We should have seen the connect probe + dir-writable + cat-existing,
    # not anything fancier.
    assert calls[0][0] == "ssh"


def test_apply_includes_pve_reload_and_post_check(
    pem_bundle: Path, patch_subprocess: Callable[..., list[list[str]]]
) -> None:
    calls = patch_subprocess(default_ok=True)
    cb = parse_pem(pem_bundle)
    result = get_driver("proxmox").apply(cb, _ctx())
    assert result.exit_code == 0, result.model_dump()
    assert result.driver == "proxmox"
    descs = [s.description for s in result.steps]
    assert "reload service" in descs
    assert "post-check" in descs
    # The reload command must be the PVE default unless overridden:
    ssh_cmds = [c[-1] for c in calls if c[0] == "ssh"]
    assert PVE_RELOAD in ssh_cmds
    assert PVE_POST_CHECK in ssh_cmds


def test_overrides_replace_pve_defaults(
    pem_bundle: Path, patch_subprocess: Callable[..., list[list[str]]]
) -> None:
    calls = patch_subprocess(default_ok=True)
    cb = parse_pem(pem_bundle)
    custom_reload = "systemctl reload some-other-service"
    custom_cert = "/var/lib/custom/pveproxy.pem"
    result = get_driver("proxmox").apply(
        cb,
        _ctx(reload_cmd=custom_reload, cert_dest=custom_cert),
    )
    assert result.exit_code == 0
    ssh_cmds = [c[-1] for c in calls if c[0] == "ssh"]
    assert custom_reload in ssh_cmds
    assert PVE_RELOAD not in ssh_cmds
    # New cert path appears in a finalise command
    assert any(custom_cert in c for c in ssh_cmds)
    assert not any(PVE_CERT_PATH in c for c in ssh_cmds)


def test_verify_uses_pve_paths(
    patch_subprocess: Callable[..., list[list[str]]],
) -> None:
    calls = patch_subprocess(default_ok=True)
    result = get_driver("proxmox").verify(_ctx())
    assert result.ok is True
    # Two test -f probes per defaults (cert + key):
    test_probes = [c for c in calls if c[0] == "ssh" and "test -f" in c[-1]]
    assert len(test_probes) == 2
    assert any(PVE_CERT_PATH in c[-1] for c in test_probes)
    assert any(PVE_KEY_PATH in c[-1] for c in test_probes)
