from __future__ import annotations

import json
from pathlib import Path

from certswap.drivers.base import ApplyResult, StepResult, TargetContext
from certswap.evidence import build_record, evidence_dirname, write_evidence
from certswap.ingest.pem import parse_pem


def test_evidence_record_round_trip(pem_bundle: Path, tmp_path: Path) -> None:
    cb = parse_pem(pem_bundle)
    ctx = TargetContext(
        driver="local",
        identifier=str(tmp_path / "deploy"),
        options={"dest": str(tmp_path / "deploy")},
    )
    result = ApplyResult(
        driver="local",
        identifier=ctx.identifier,
        steps=[StepResult(description="write cert", duration_ms=5)],
        exit_code=0,
    )
    record = build_record(cb, ctx, result)
    out = write_evidence(record, tmp_path / "evidence")
    assert out.is_dir()
    assert (out / "evidence.json").is_file()
    assert (out / "evidence.md").is_file()
    payload = json.loads((out / "evidence.json").read_text())
    assert payload["target"]["driver"] == "local"
    assert payload["bundle"]["subject_cn"] == "test.certswap.example"


def test_evidence_dirname_slugs_identifier(pem_bundle: Path, tmp_path: Path) -> None:
    cb = parse_pem(pem_bundle)
    ctx = TargetContext(
        driver="local",
        identifier="/some path/with spaces",
        options={"dest": "/some path/with spaces"},
    )
    result = ApplyResult(driver="local", identifier=ctx.identifier)
    record = build_record(cb, ctx, result)
    name = evidence_dirname(record)
    # Slugified — no spaces, no leading slashes that would land outside the
    # evidence root.
    assert "/" not in name
    assert " " not in name
    assert "local" in name
