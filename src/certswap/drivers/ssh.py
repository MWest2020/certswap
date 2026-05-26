"""SSH driver: write cert + key to a remote host via ssh + scp.

The host argument is always a name (or alias) resolved by
``~/.ssh/config``. There is no ``--ssh-key`` flag in v1 — IdentityFile,
ProxyJump, ControlMaster, etc. live in the operator's ssh config.
"""

from __future__ import annotations

from datetime import UTC, datetime

from certswap.drivers._ssh_apply import (
    install_one,
    rollback_backups,
    run_remote_step,
)
from certswap.drivers._ssh_options import (
    SshOptions,
    planned_files,
    remote_dirname,
    verify_targets,
)
from certswap.drivers._ssh_shell import ensure_ssh_available, quote, ssh_run
from certswap.drivers.base import (
    ApplyResult,
    CheckResult,
    Plan,
    PlanStep,
    TargetContext,
    VerifyResult,
    register,
)
from certswap.models import CertBundle


def _timestamp_suffix() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


class SshDriver:
    name: str = "ssh"

    def plan(self, bundle: CertBundle, ctx: TargetContext) -> Plan:
        opts = SshOptions.from_context(ctx)
        ensure_ssh_available()
        plan = Plan(driver=self.name, identifier=ctx.identifier)

        connect = ssh_run(opts.host, "true")
        if not connect.ok:
            plan.blockers.append(f"ssh connect failed: {connect.stderr_str()}")
            return plan
        plan.steps.append(
            PlanStep(description="ssh connect", before=None, would_do=connect.printable)
        )

        files = planned_files(bundle, opts)
        if not files:
            plan.blockers.append(
                "no destination paths configured "
                "(need --cert-dest / --key-dest / --combined-dest)"
            )
            return plan

        for label, dst, mode, _data in files:
            parent = remote_dirname(dst)
            check = ssh_run(
                opts.host, f"test -d {quote(parent)} && test -w {quote(parent)}"
            )
            if not check.ok:
                plan.blockers.append(f"{parent} not writable on {opts.host} for {label}")
                continue

            existing = ssh_run(
                opts.host, f"test -f {quote(dst)} && cat {quote(dst)} || true"
            )
            has_existing = bool(existing.stdout_str().strip())
            plan.steps.append(
                PlanStep(
                    description=f"write {label} to {dst} (mode {oct(mode)})",
                    before="(existing)" if has_existing else None,
                    would_do=f"scp + atomic mv into {dst}",
                )
            )

        if opts.pre_check_cmd:
            pre = ssh_run(opts.host, opts.pre_check_cmd)
            if not pre.ok:
                plan.blockers.append(f"pre-check failed: {pre.stderr_str()}")
            else:
                plan.steps.append(
                    PlanStep(
                        description="pre-check",
                        before=None,
                        would_do=opts.pre_check_cmd,
                    )
                )

        if opts.reload_cmd:
            plan.steps.append(
                PlanStep(description="reload service", before=None, would_do=opts.reload_cmd)
            )
        if opts.post_check_cmd:
            plan.steps.append(
                PlanStep(description="post-check", before=None, would_do=opts.post_check_cmd)
            )
        return plan

    def apply(self, bundle: CertBundle, ctx: TargetContext) -> ApplyResult:
        opts = SshOptions.from_context(ctx)
        ensure_ssh_available()
        result = ApplyResult(driver=self.name, identifier=ctx.identifier)
        files = planned_files(bundle, opts)
        if not files:
            result.exit_code = 10
            return result

        suffix = _timestamp_suffix()
        backups: list[tuple[str, str]] = []

        for label, dst, mode, data in files:
            if not install_one(opts, label, dst, mode, data, suffix, result, backups):
                rollback_backups(opts.host, backups, result)
                result.exit_code = 50
                return result

        if opts.reload_cmd and not run_remote_step(
            opts.host, "reload service", opts.reload_cmd, result
        ):
            rollback_backups(opts.host, backups, result)
            result.exit_code = 50
            return result

        if opts.post_check_cmd and not run_remote_step(
            opts.host, "post-check", opts.post_check_cmd, result
        ):
            rollback_backups(opts.host, backups, result)
            result.exit_code = 60
            return result

        result.verify = self.verify(ctx)
        if not result.verify.ok:
            result.exit_code = 60
        return result

    def verify(self, ctx: TargetContext) -> VerifyResult:
        opts = SshOptions.from_context(ctx)
        checks: list[CheckResult] = []
        all_ok = True
        for label, dst in verify_targets(opts):
            run = ssh_run(opts.host, f"test -f {quote(dst)}")
            ok = run.ok
            checks.append(
                CheckResult(
                    name=f"{label} present at {opts.host}:{dst}",
                    ok=ok,
                    detail=None if ok else run.stderr_str() or "file missing",
                )
            )
            if not ok:
                all_ok = False
        return VerifyResult(ok=all_ok, checks=checks)


register(SshDriver())

__all__ = ["SshDriver"]
