from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from certswap.cli import app

runner = CliRunner()


def test_inspect_pem_rich_output(pem_bundle: Path) -> None:
    result = runner.invoke(app, ["inspect", str(pem_bundle)])
    assert result.exit_code == 0, result.output
    assert "test.certswap.example" in result.output
    assert "SHA256:" in result.output


def test_inspect_pem_json_output(pem_bundle: Path) -> None:
    result = runner.invoke(app, ["inspect", str(pem_bundle), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["leaf"]["subject_cn"] == "test.certswap.example"
    assert payload["validation"]["key_matches_leaf"] is True
    assert "fingerprint_sha256" in payload["leaf"]


def test_inspect_pfx_with_password_env(
    pfx_bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CSW_TEST_PASS", "hunter2")
    result = runner.invoke(
        app,
        ["inspect", str(pfx_bundle), "--password-env", "CSW_TEST_PASS", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["source"]["format"] == "pfx"
    assert payload["validation"]["key_matches_leaf"] is True


def test_inspect_pfx_with_password_stdin(pfx_bundle: Path) -> None:
    result = runner.invoke(
        app,
        ["inspect", str(pfx_bundle), "--password-stdin", "--json"],
        input="hunter2\n",
    )
    assert result.exit_code == 0, result.output


def test_inspect_password_conflict_errors(pfx_bundle: Path) -> None:
    result = runner.invoke(
        app,
        [
            "inspect",
            str(pfx_bundle),
            "--password-stdin",
            "--password-env",
            "X",
        ],
    )
    assert result.exit_code != 0
    assert "not both" in result.output or "Usage" in result.output


def test_inspect_directory(separate_files_dir: Path) -> None:
    result = runner.invoke(app, ["inspect", str(separate_files_dir), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["source"]["format"] == "separate_files"
