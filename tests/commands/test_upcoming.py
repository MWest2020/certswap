from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from certswap.cli import app
from certswap.state import StateEntry, append

runner = CliRunner()


def _entry(target: str, ident: str, fp: str, days: int) -> StateEntry:
    now = datetime.now(UTC)
    return StateEntry(
        timestamp=now,
        target=target,
        identifier=ident,
        fingerprint=fp,
        not_after=now + timedelta(days=days),
        evidence_dir="evidence-stub",
    )


def test_upcoming_empty_state_says_none(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    result = runner.invoke(app, ["upcoming", "--state", str(state_path)])
    assert result.exit_code == 0
    assert "none" in result.output.lower()


def test_upcoming_filters_and_sorts(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    append(_entry("local", "deploy-a", "aaa", 5), path=state_path)
    append(_entry("local", "deploy-b", "bbb", 90), path=state_path)
    append(_entry("k8s", "ns/x@ctx", "ccc", 30), path=state_path)

    result = runner.invoke(
        app, ["upcoming", "--state", str(state_path), "--within-days", "60", "--json"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["within_days"] == 60
    fps = [d["fingerprint"] for d in payload["deployments"]]
    # `bbb` (90 days) excluded; the rest sorted by expiry ascending
    assert fps == ["aaa", "ccc"]
    days = [d["days_remaining"] for d in payload["deployments"]]
    assert days[0] <= days[1]


def test_upcoming_human_table_shows_targets(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    append(_entry("ssh", "host:/etc/tls/x.pem", "deadbeef" * 8, 7), path=state_path)
    result = runner.invoke(
        app, ["upcoming", "--state", str(state_path), "--within-days", "30"]
    )
    assert result.exit_code == 0
    assert "ssh" in result.output
    assert "/etc/tls/x.pem" in result.output


def test_upcoming_within_days_window(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    append(_entry("local", "deploy-soon", "aaa", 14), path=state_path)
    append(_entry("local", "deploy-late", "bbb", 45), path=state_path)
    # narrow window: 30 days
    r1 = runner.invoke(
        app, ["upcoming", "--state", str(state_path), "--within-days", "30", "--json"]
    )
    p1 = json.loads(r1.stdout)
    assert [d["fingerprint"] for d in p1["deployments"]] == ["aaa"]
    # wider: 60 days
    r2 = runner.invoke(
        app, ["upcoming", "--state", str(state_path), "--within-days", "60", "--json"]
    )
    p2 = json.loads(r2.stdout)
    assert {d["fingerprint"] for d in p2["deployments"]} == {"aaa", "bbb"}
