from __future__ import annotations

from typer.testing import CliRunner

from certswap import __version__
from certswap.cli import app

runner = CliRunner()


def test_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    # Typer exits 2 when no_args_is_help triggers (usage message printed).
    assert result.exit_code == 2
    assert "certswap" in result.stdout.lower()
