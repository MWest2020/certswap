"""Evidence writers: ``evidence.json`` + ``evidence.md`` per apply."""

from __future__ import annotations

import getpass
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from certswap import __version__
from certswap.drivers.base import ApplyResult, TargetContext
from certswap.models import CertBundle


class BundleSummary(BaseModel):
    subject_cn: str | None
    sans: list[str]
    issuer_cn: str
    not_before: str
    not_after: str
    fingerprint_sha256: str
    canonical_hash: str
    source_format: str
    source_path: str
    needs_legacy_mode: bool


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    operator: str
    tool_version: str = Field(default=__version__)
    target: TargetContext
    bundle: BundleSummary
    apply: ApplyResult


_SLUG_RE = re.compile(r"[^a-zA-Z0-9._@-]+")


def _slugify(value: str) -> str:
    return _SLUG_RE.sub("-", value).strip("-") or "unknown"


def _bundle_summary(bundle: CertBundle) -> BundleSummary:
    return BundleSummary(
        subject_cn=bundle.subject_cn(),
        sans=bundle.sans(),
        issuer_cn=bundle.issuer_cn(),
        not_before=bundle.not_before().isoformat(),
        not_after=bundle.not_after().isoformat(),
        fingerprint_sha256=bundle.fingerprint_sha256(),
        canonical_hash=bundle.canonical_hash(),
        source_format=bundle.source_format.value,
        source_path=str(bundle.source_path),
        needs_legacy_mode=bundle.needs_legacy_mode,
    )


def build_record(
    bundle: CertBundle, ctx: TargetContext, result: ApplyResult
) -> EvidenceRecord:
    try:
        operator = getpass.getuser()
    except (KeyError, OSError):
        operator = "unknown"
    return EvidenceRecord(
        operator=operator,
        target=ctx,
        bundle=_bundle_summary(bundle),
        apply=result,
    )


def evidence_dirname(record: EvidenceRecord) -> str:
    ts = record.timestamp_utc.strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}-{_slugify(record.target.driver)}-{_slugify(record.target.identifier)}"


def write_evidence(record: EvidenceRecord, evidence_root: Path) -> Path:
    target_dir = evidence_root / evidence_dirname(record)
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "evidence.json").write_text(
        json.dumps(_to_jsonable(record.model_dump()), indent=2, default=str)
    )
    (target_dir / "evidence.md").write_text(_render_markdown(record))
    return target_dir


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _render_markdown(record: EvidenceRecord) -> str:
    lines: list[str] = []
    lines.append(f"# certswap evidence: {record.target.driver} / {record.target.identifier}")
    lines.append("")
    lines.append(f"- Timestamp (UTC): {record.timestamp_utc.isoformat()}")
    lines.append(f"- Operator: {record.operator}")
    lines.append(f"- Tool version: {record.tool_version}")
    lines.append(f"- Target driver: `{record.target.driver}`")
    lines.append(f"- Identifier: `{record.target.identifier}`")
    lines.append("")
    lines.append("## Bundle")
    lines.append("")
    b = record.bundle
    lines.append(f"- Subject CN: `{b.subject_cn}`")
    lines.append(f"- SANs: `{', '.join(b.sans) or '—'}`")
    lines.append(f"- Issuer: `{b.issuer_cn}`")
    lines.append(f"- Valid: `{b.not_before}` → `{b.not_after}`")
    lines.append(f"- Fingerprint (SHA256): `{b.fingerprint_sha256}`")
    lines.append(f"- Canonical hash: `{b.canonical_hash}`")
    lines.append(f"- Source format: `{b.source_format}` (legacy mode: {b.needs_legacy_mode})")
    lines.append(f"- Source path: `{b.source_path}`")
    lines.append("")
    lines.append("## Actions")
    lines.append("")
    for idx, step in enumerate(record.apply.steps, start=1):
        status = "OK" if step.ok else "FAIL"
        lines.append(f"{idx}. **{status}** — {step.description} ({step.duration_ms} ms)")
        if step.before:
            lines.append(f"   - before: `{step.before}`")
        if step.after:
            lines.append(f"   - after: `{step.after}`")
        if step.error:
            lines.append(f"   - error: `{step.error}`")
    lines.append("")
    if record.apply.verify is not None:
        lines.append("## Verification")
        lines.append("")
        for chk in record.apply.verify.checks:
            mark = "✓" if chk.ok else "✗"
            detail = f" — {chk.detail}" if chk.detail else ""
            lines.append(f"- {mark} {chk.name}{detail}")
        lines.append("")
    lines.append(f"## Exit code: {record.apply.exit_code}")
    lines.append("")
    return "\n".join(lines)


def default_evidence_root() -> Path:
    return Path.home() / ".certswap" / "evidence"
