"""ssh / scp shell-out helpers.

Every remote action is a literal ``ssh <host> <cmd>`` or ``scp <src>
<host>:<dst>`` you could copy-paste in a terminal. ``~/.ssh/config``
resolves the user, ProxyJump, IdentityFile, ControlMaster, etc.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

SSH_BASE_OPTS: tuple[str, ...] = (
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
)


@dataclass(frozen=True)
class ShellRun:
    """Result of a single ssh/scp invocation, structured for evidence."""

    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def printable(self) -> str:
        return shlex.join(self.argv)

    def stderr_str(self) -> str:
        return self.stderr.decode("utf-8", errors="replace").strip()

    def stdout_str(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")


def ensure_ssh_available() -> None:
    """Raise ``RuntimeError`` if ssh / scp are not on PATH."""
    for binary in ("ssh", "scp"):
        if shutil.which(binary) is None:
            raise RuntimeError(f"{binary} not on PATH; ssh driver cannot run")


def ssh_run(host: str, remote_cmd: str, *, timeout: float = 60.0) -> ShellRun:
    """Run ``remote_cmd`` on ``host`` via ssh. ``remote_cmd`` is a literal
    shell snippet evaluated by the remote login shell; build it with
    ``shlex.quote`` for anything that's not statically known.
    """
    argv = ["ssh", *SSH_BASE_OPTS, host, remote_cmd]
    proc = subprocess.run(
        argv, capture_output=True, check=False, timeout=timeout
    )
    return ShellRun(argv=argv, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def scp_put(local: Path, host: str, remote_path: str, *, timeout: float = 120.0) -> ShellRun:
    """Upload ``local`` to ``host:remote_path``."""
    argv = ["scp", *SSH_BASE_OPTS, str(local), f"{host}:{remote_path}"]
    proc = subprocess.run(
        argv, capture_output=True, check=False, timeout=timeout
    )
    return ShellRun(argv=argv, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def quote(value: str) -> str:
    """Convenience re-export of shlex.quote for callers building commands."""
    return shlex.quote(value)
