"""Smoke tests: end-to-end CLI round-trips through the real wiring.

Each test drives the actual ``certswap`` Typer app the way a user would —
no mocking of the local driver — proving that ingest → apply → verify holds
together for every input format the README advertises. Run just these with
``uv run pytest -m smoke``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from certswap.cli import app

pytestmark = pytest.mark.smoke

runner = CliRunner()


def _apply_local(
    bundle: Path, dest: Path, evidence: Path, *, extra: list[str] | None = None
) -> None:
    """apply local <bundle> --dest ..., then assert files + evidence landed."""
    args = [
        "apply",
        "local",
        str(bundle),
        "--dest",
        str(dest),
        "--yes",
        "--evidence-dir",
        str(evidence),
        *(extra or []),
    ]
    result = runner.invoke(app, args, input="hunter2")
    assert result.exit_code == 0, result.output
    assert (dest / "fullchain.pem").is_file()
    assert (dest / "fullchain.key").is_file()
    evidence_run = next(evidence.iterdir())
    assert (evidence_run / "evidence.json").is_file()
    assert (evidence_run / "evidence.md").is_file()


def _verify_local_ok(dest: Path) -> None:
    result = runner.invoke(app, ["verify", "local", "--dest", str(dest), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["ok"] is True


def test_smoke_pem_bundle_roundtrip(pem_bundle: Path, tmp_path: Path) -> None:
    dest = tmp_path / "deploy"
    _apply_local(pem_bundle, dest, tmp_path / "evidence")
    _verify_local_ok(dest)


def test_smoke_pfx_bundle_roundtrip(pfx_bundle: Path, tmp_path: Path) -> None:
    """PFX needs the password off stdin — exercises the ingest password path."""
    dest = tmp_path / "deploy"
    _apply_local(pfx_bundle, dest, tmp_path / "evidence", extra=["--password-stdin"])
    _verify_local_ok(dest)


def test_smoke_zip_bundle_roundtrip(zip_bundle: Path, tmp_path: Path) -> None:
    dest = tmp_path / "deploy"
    _apply_local(zip_bundle, dest, tmp_path / "evidence")
    _verify_local_ok(dest)


def test_smoke_separate_files_roundtrip(
    separate_files_dir: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "deploy"
    _apply_local(separate_files_dir, dest, tmp_path / "evidence")
    _verify_local_ok(dest)


def test_smoke_inspect_reports_leaf_and_chain(pem_bundle: Path) -> None:
    result = runner.invoke(app, ["inspect", str(pem_bundle), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    # Leaf SAN from the test PKI surfaces, and the chain carries the intermediate.
    assert payload["leaf"]["sans"] == ["test.certswap.example"]
    assert payload["chain"]["length"] >= 1
    assert payload["validation"]["key_matches_leaf"] is True
