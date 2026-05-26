from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from certswap.drivers import get_driver
from certswap.drivers.base import TargetContext
from certswap.ingest.pem import parse_pem


def _make_completed(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _ctx(**opts: Any) -> TargetContext:
    base = {"host": "test-host"}
    base.update(opts)
    return TargetContext(driver="ssh", identifier=f"{base['host']}:test", options=base)


@pytest.fixture
def patch_subprocess(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[list[str]]]:
    """Patch subprocess.run inside _ssh_shell and record argv lists.

    Returns a closure that sets the response sequence and returns the
    recorder. Each call to subprocess.run consumes one response from the
    provided iterable (or the default success response).
    """
    calls: list[list[str]] = []

    def installer(
        responses: list[subprocess.CompletedProcess[bytes]] | None = None,
        default_ok: bool = True,
    ) -> list[list[str]]:
        iterator = iter(responses or [])

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            calls.append(list(argv))
            try:
                resp = next(iterator)
            except StopIteration:
                resp = _make_completed(0 if default_ok else 1)
            resp.args = argv
            return resp

        monkeypatch.setattr("certswap.drivers._ssh_shell.subprocess.run", fake_run)
        return calls

    return installer


def test_plan_succeeds_when_connect_ok(
    pem_bundle: Path, patch_subprocess: Callable[..., list[list[str]]]
) -> None:
    # connect ok, parent dir writable, no existing file, no pre-check
    responses = [
        _make_completed(0),  # ssh host true
        _make_completed(0),  # test -d/-w
        _make_completed(0, stdout=b""),  # cat existing
        _make_completed(0),  # test -d/-w
        _make_completed(0, stdout=b""),  # cat existing
    ]
    calls = patch_subprocess(responses)
    cb = parse_pem(pem_bundle)
    ctx = _ctx(cert_dest="/etc/nginx/tls/example.pem", key_dest="/etc/nginx/tls/example.key")
    plan = get_driver("ssh").plan(cb, ctx)
    assert plan.blockers == []
    assert any("write cert" in s.description for s in plan.steps)
    assert any("write key" in s.description for s in plan.steps)
    # First call is the connect probe `ssh ... test-host true`
    assert calls[0][0] == "ssh"
    assert calls[0][-2] == "test-host"
    assert calls[0][-1] == "true"


def test_plan_blocks_on_connect_failure(
    pem_bundle: Path, patch_subprocess: Callable[..., list[list[str]]]
) -> None:
    patch_subprocess([_make_completed(255, stderr=b"connect failed")])
    cb = parse_pem(pem_bundle)
    ctx = _ctx(cert_dest="/etc/tls/x.pem", key_dest="/etc/tls/x.key")
    plan = get_driver("ssh").plan(cb, ctx)
    assert plan.is_blocked
    assert any("ssh connect failed" in b for b in plan.blockers)


def test_plan_blocks_when_no_destinations(
    pem_bundle: Path, patch_subprocess: Callable[..., list[list[str]]]
) -> None:
    patch_subprocess([_make_completed(0)])
    cb = parse_pem(pem_bundle)
    ctx = _ctx()  # no dest paths
    plan = get_driver("ssh").plan(cb, ctx)
    assert plan.is_blocked
    assert any("no destination paths" in b for b in plan.blockers)


def test_apply_happy_path_uses_atomic_mv_and_chmod(
    pem_bundle: Path, patch_subprocess: Callable[..., list[list[str]]]
) -> None:
    # Sequence:
    # 1. ssh test -f / cp backup (no existing → rc=1 still ok via `|| true`)
    # 2. scp put cert
    # 3. ssh chmod + mv cert
    # 4. ssh test -f / cp backup for key (rc=1, `|| true`)
    # 5. scp put key
    # 6. ssh chmod + mv key
    # 7. verify cert (test -f)
    # 8. verify key (test -f)
    calls = patch_subprocess([], default_ok=True)
    cb = parse_pem(pem_bundle)
    ctx = _ctx(cert_dest="/etc/nginx/tls/example.pem", key_dest="/etc/nginx/tls/example.key")
    result = get_driver("ssh").apply(cb, ctx)
    assert result.exit_code == 0, result.model_dump_json(indent=2)
    # We should see scp invocations
    scp_calls = [c for c in calls if c[0] == "scp"]
    assert len(scp_calls) == 2
    # chmod + mv must reference the actual dest paths
    finalize_calls = [
        c for c in calls if c[0] == "ssh" and any("mv " in arg for arg in c)
    ]
    # shlex.quote on a /etc-style path leaves it unquoted (no special chars).
    assert any("/etc/nginx/tls/example.pem" in c[-1] for c in finalize_calls)
    assert any("/etc/nginx/tls/example.key" in c[-1] for c in finalize_calls)
    assert any("chmod 600" in c[-1] for c in finalize_calls)
    assert any("chmod 644" in c[-1] for c in finalize_calls)


def test_apply_rolls_back_on_install_failure(
    pem_bundle: Path,
    patch_subprocess: Callable[..., list[list[str]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the second install fails, the first install's backup should
    be restored.
    """
    # Stub each helper directly for finer control.
    from certswap.drivers import _ssh_apply

    install_calls: list[tuple[str, str]] = []
    rollback_calls: list[list[tuple[str, str]]] = []

    def fake_install(opts, label, dst, mode, data, suffix, result, backups):  # type: ignore[no-untyped-def]
        install_calls.append((label, dst))
        # Simulate that the first install creates a backup, then the
        # second install fails.
        if label == "cert":
            backups.append((dst, f"{dst}.bak-{suffix}"))
            return True
        return False

    def fake_rollback(host, backups, result):  # type: ignore[no-untyped-def]
        rollback_calls.append(list(backups))

    monkeypatch.setattr(_ssh_apply, "install_one", fake_install)
    monkeypatch.setattr(_ssh_apply, "rollback_backups", fake_rollback)
    # Also re-bind in the ssh module since it imported the symbols by name.
    from certswap.drivers import ssh as ssh_mod

    monkeypatch.setattr(ssh_mod, "install_one", fake_install)
    monkeypatch.setattr(ssh_mod, "rollback_backups", fake_rollback)

    patch_subprocess([], default_ok=True)
    cb = parse_pem(pem_bundle)
    ctx = _ctx(cert_dest="/etc/tls/x.pem", key_dest="/etc/tls/x.key")
    result = get_driver("ssh").apply(cb, ctx)
    assert result.exit_code == 50
    assert install_calls == [("cert", "/etc/tls/x.pem"), ("key", "/etc/tls/x.key")]
    assert len(rollback_calls) == 1
    assert rollback_calls[0] == [("/etc/tls/x.pem", "/etc/tls/x.pem.bak-" + rollback_calls[0][0][1].rsplit("-", 1)[1])]


def test_verify_calls_test_f_per_target(
    patch_subprocess: Callable[..., list[list[str]]],
) -> None:
    calls = patch_subprocess([], default_ok=True)
    ctx = _ctx(cert_dest="/etc/tls/x.pem", key_dest="/etc/tls/x.key")
    result = get_driver("ssh").verify(ctx)
    assert result.ok is True
    # One test -f per destination
    test_calls = [c for c in calls if c[0] == "ssh" and "test -f" in c[-1]]
    assert len(test_calls) == 2


def test_verify_reports_missing_files(
    patch_subprocess: Callable[..., list[list[str]]],
) -> None:
    patch_subprocess(
        [
            _make_completed(1, stderr=b""),  # cert missing
            _make_completed(0),  # key present
        ],
        default_ok=True,
    )
    ctx = _ctx(cert_dest="/etc/tls/x.pem", key_dest="/etc/tls/x.key")
    result = get_driver("ssh").verify(ctx)
    assert result.ok is False
    failed = [c for c in result.checks if not c.ok]
    assert len(failed) == 1
    assert "cert present" in failed[0].name
