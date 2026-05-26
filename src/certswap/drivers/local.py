"""Local-filesystem driver.

Writes the bundle to a directory: fullchain (or leaf-only when no chain),
private key, and optionally a combined ``leaf+chain+key`` PEM for HAProxy
style targets.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from certswap.drivers.base import (
    ApplyResult,
    CheckResult,
    Plan,
    PlanStep,
    StepResult,
    TargetContext,
    VerifyResult,
    register,
)
from certswap.models import CertBundle


@dataclass(frozen=True)
class LocalOptions:
    dest: Path
    cert_name: str = "fullchain"
    combined: bool = False
    force: bool = False

    @classmethod
    def from_context(cls, ctx: TargetContext) -> LocalOptions:
        opts: dict[str, Any] = ctx.options
        dest = opts.get("dest")
        if dest is None:
            raise ValueError("local driver requires `dest` in TargetContext.options")
        return cls(
            dest=Path(dest),
            cert_name=str(opts.get("cert_name") or "fullchain"),
            combined=bool(opts.get("combined", False)),
            force=bool(opts.get("force", False)),
        )


def _expected_paths(opts: LocalOptions) -> dict[str, Path]:
    paths = {
        "cert": opts.dest / f"{opts.cert_name}.pem",
        "key": opts.dest / f"{opts.cert_name}.key",
    }
    if opts.combined:
        paths["combined"] = opts.dest / f"{opts.cert_name}-combined.pem"
    return paths


def _describe_existing(path: Path) -> str | None:
    if not path.exists():
        return None
    return f"{path} ({path.stat().st_size} bytes)"


class LocalDriver:
    name: str = "local"

    def plan(self, bundle: CertBundle, ctx: TargetContext) -> Plan:
        opts = LocalOptions.from_context(ctx)
        plan = Plan(driver=self.name, identifier=ctx.identifier)
        if not opts.dest.exists():
            plan.steps.append(
                PlanStep(
                    description="create destination directory",
                    before=None,
                    would_do=f"mkdir -p {opts.dest}",
                )
            )
        elif not opts.dest.is_dir():
            plan.blockers.append(f"{opts.dest} exists and is not a directory")
            return plan

        targets = _expected_paths(opts)
        for label, path in targets.items():
            existing = _describe_existing(path)
            if existing and not opts.force:
                plan.warnings.append(
                    f"{label} already at {path}; use --force or expect overwrite"
                )
            plan.steps.append(
                PlanStep(
                    description=f"write {label}",
                    before=existing,
                    would_do=f"write {path}",
                )
            )
        return plan

    def apply(self, bundle: CertBundle, ctx: TargetContext) -> ApplyResult:
        opts = LocalOptions.from_context(ctx)
        result = ApplyResult(driver=self.name, identifier=ctx.identifier)
        opts.dest.mkdir(parents=True, exist_ok=True)
        targets = _expected_paths(opts)

        for label, path in targets.items():
            start = time.perf_counter()
            before = _describe_existing(path)
            try:
                if label == "cert":
                    _atomic_write(path, bundle.to_pem_fullchain(), mode=0o644)
                elif label == "key":
                    _atomic_write(path, bundle.to_pem_key(), mode=0o600)
                elif label == "combined":
                    data = (
                        bundle.to_pem_fullchain()
                        + bundle.to_pem_key()
                    )
                    _atomic_write(path, data, mode=0o600)
                else:  # pragma: no cover - exhaustive
                    raise ValueError(f"unknown target label: {label}")
            except OSError as exc:
                result.steps.append(
                    StepResult(
                        description=f"write {label}",
                        before=before,
                        after=None,
                        duration_ms=int((time.perf_counter() - start) * 1000),
                        ok=False,
                        error=str(exc),
                    )
                )
                result.exit_code = 50
                return result

            result.steps.append(
                StepResult(
                    description=f"write {label}",
                    before=before,
                    after=_describe_existing(path),
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    ok=True,
                )
            )

        result.verify = self.verify(ctx)
        if not result.verify.ok:
            result.exit_code = 60
        return result

    def verify(self, ctx: TargetContext) -> VerifyResult:
        opts = LocalOptions.from_context(ctx)
        targets = _expected_paths(opts)
        checks: list[CheckResult] = []
        all_ok = True
        for label, path in targets.items():
            exists = path.is_file()
            checks.append(
                CheckResult(
                    name=f"{label} present at {path}",
                    ok=exists,
                    detail=None if exists else "file missing",
                )
            )
            if not exists:
                all_ok = False
        return VerifyResult(ok=all_ok, checks=checks)


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    """Write ``data`` to ``path`` atomically, with ``mode`` from creation.

    Creating the tmp file with the target mode (rather than chmod-after)
    closes the brief window in which a 0o600 key would otherwise be
    world-readable due to the default umask.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        # chmod again in case an existing tmpfile predated this run with
        # different perms (O_TRUNC reuses the inode + perms).
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise


_DRIVER = LocalDriver()
register(_DRIVER)


__all__ = ["LocalDriver", "LocalOptions"]
