"""Apply-time helpers for the ssh driver: scp + atomic mv + rollback."""

from __future__ import annotations

import secrets
import tempfile
import time
from pathlib import Path

from certswap.drivers._ssh_options import SshOptions
from certswap.drivers._ssh_shell import quote, scp_put, ssh_run
from certswap.drivers.base import ApplyResult, StepResult


def install_one(
    opts: SshOptions,
    label: str,
    dst: str,
    mode: int,
    data: bytes,
    suffix: str,
    result: ApplyResult,
    backups: list[tuple[str, str]],
) -> bool:
    """Install one file. Returns True on success, False on failure (and the
    apply caller is responsible for invoking ``rollback_backups``).
    """
    start = time.perf_counter()

    backup = f"{dst}.bak-{suffix}"
    backup_run = ssh_run(
        opts.host,
        f"test -f {quote(dst)} && cp -p {quote(dst)} {quote(backup)} || true",
    )
    if backup_run.ok:
        backups.append((dst, backup))

    with tempfile.NamedTemporaryFile(prefix="certswap-", delete=False) as tmp:
        tmp.write(data)
        local_tmp = Path(tmp.name)
    try:

        remote_tmp = f"/tmp/certswap-{secrets.token_hex(8)}"  # noqa: S108
        upload = scp_put(local_tmp, opts.host, remote_tmp)
        if not upload.ok:
            _record(
                result,
                description=f"scp {label}",
                ok=False,
                start=start,
                error=upload.stderr_str(),
            )
            return False

        chown_clause = ""
        if opts.owner or opts.group:
            who = f"{opts.owner or ''}:{opts.group or ''}".strip(":")
            chown_clause = f" && chown {quote(who)} {quote(remote_tmp)}"
        finalize = (
            f"chmod {oct(mode)[2:]} {quote(remote_tmp)}"
            f"{chown_clause}"
            f" && mv {quote(remote_tmp)} {quote(dst)}"
        )
        run = ssh_run(opts.host, finalize)
        if not run.ok:
            ssh_run(opts.host, f"rm -f {quote(remote_tmp)}")
            _record(
                result,
                description=f"install {label}",
                ok=False,
                start=start,
                error=run.stderr_str(),
            )
            return False

        _record(
            result,
            description=f"install {label}",
            ok=True,
            start=start,
            after=dst,
        )
        return True
    finally:
        local_tmp.unlink(missing_ok=True)


def run_remote_step(host: str, label: str, cmd: str, result: ApplyResult) -> bool:
    start = time.perf_counter()
    run = ssh_run(host, cmd)
    _record(
        result,
        description=label,
        ok=run.ok,
        start=start,
        after=cmd,
        error=None if run.ok else run.stderr_str(),
    )
    return run.ok


def rollback_backups(
    host: str, backups: list[tuple[str, str]], result: ApplyResult
) -> None:
    for dst, backup in reversed(backups):
        start = time.perf_counter()
        run = ssh_run(
            host, f"test -f {quote(backup)} && mv {quote(backup)} {quote(dst)} || true"
        )
        _record(
            result,
            description=f"rollback {dst}",
            ok=run.ok,
            start=start,
            before=backup,
            after=dst,
            error=None if run.ok else run.stderr_str(),
        )


def _record(
    result: ApplyResult,
    *,
    description: str,
    ok: bool,
    start: float,
    before: str | None = None,
    after: str | None = None,
    error: str | None = None,
) -> None:
    result.steps.append(
        StepResult(
            description=description,
            before=before,
            after=after,
            duration_ms=int((time.perf_counter() - start) * 1000),
            ok=ok,
            error=error,
        )
    )
