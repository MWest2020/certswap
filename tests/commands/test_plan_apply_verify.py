from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from certswap.cli import app

runner = CliRunner()


def test_plan_local_lists_steps(pem_bundle: Path, tmp_path: Path) -> None:
    dest = tmp_path / "deploy"
    result = runner.invoke(app, ["plan", "local", str(pem_bundle), "--dest", str(dest)])
    assert result.exit_code == 0, result.output
    assert "create destination directory" in result.output
    assert "write cert" in result.output


def test_plan_local_json(pem_bundle: Path, tmp_path: Path) -> None:
    dest = tmp_path / "deploy"
    result = runner.invoke(
        app, ["plan", "local", str(pem_bundle), "--dest", str(dest), "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["driver"] == "local"
    assert any(s["description"] == "write cert" for s in payload["steps"])


def test_apply_local_writes_files_and_evidence(
    pem_bundle: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "deploy"
    evidence_root = tmp_path / "evidence"
    result = runner.invoke(
        app,
        [
            "apply",
            "local",
            str(pem_bundle),
            "--dest",
            str(dest),
            "--yes",
            "--evidence-dir",
            str(evidence_root),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (dest / "fullchain.pem").is_file()
    assert (dest / "fullchain.key").is_file()
    # Evidence written
    subdirs = list(evidence_root.iterdir())
    assert len(subdirs) == 1
    assert (subdirs[0] / "evidence.json").is_file()
    assert (subdirs[0] / "evidence.md").is_file()


def test_verify_local_passes_after_apply(pem_bundle: Path, tmp_path: Path) -> None:
    dest = tmp_path / "deploy"
    apply_result = runner.invoke(
        app,
        [
            "apply",
            "local",
            str(pem_bundle),
            "--dest",
            str(dest),
            "--yes",
            "--evidence-dir",
            str(tmp_path / "evidence"),
        ],
    )
    assert apply_result.exit_code == 0, apply_result.output

    verify_result = runner.invoke(app, ["verify", "local", "--dest", str(dest), "--json"])
    assert verify_result.exit_code == 0, verify_result.output
    payload = json.loads(verify_result.stdout)
    assert payload["ok"] is True


def test_verify_local_fails_when_nothing_deployed(tmp_path: Path) -> None:
    dest = tmp_path / "nothing"
    result = runner.invoke(app, ["verify", "local", "--dest", str(dest)])
    assert result.exit_code == 60
