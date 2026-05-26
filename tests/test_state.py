from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from certswap.state import State, StateEntry, append, load, upcoming


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


def test_append_and_load(tmp_path: Path) -> None:
    p = tmp_path / "state.json"
    s = append(_entry("local", "deploy-a", "abc", 100), path=p)
    assert len(s.deployments) == 1
    loaded = load(p)
    assert len(loaded.deployments) == 1
    assert loaded.deployments[0].fingerprint == "abc"


def test_append_dedupes_on_target_identifier_fingerprint(tmp_path: Path) -> None:
    p = tmp_path / "state.json"
    append(_entry("local", "deploy-a", "abc", 100), path=p)
    s = append(_entry("local", "deploy-a", "abc", 100), path=p)
    assert len(s.deployments) == 1


def test_append_distinct_fingerprint_keeps_both(tmp_path: Path) -> None:
    p = tmp_path / "state.json"
    append(_entry("local", "deploy-a", "abc", 100), path=p)
    s = append(_entry("local", "deploy-a", "def", 200), path=p)
    assert len(s.deployments) == 2


def test_upcoming_filters_within_window(tmp_path: Path) -> None:
    p = tmp_path / "state.json"
    append(_entry("local", "deploy-a", "abc", 30), path=p)  # within 60d
    append(_entry("local", "deploy-b", "def", 90), path=p)  # outside
    s = load(p)
    soon = upcoming(within_days=60, state=s)
    assert len(soon) == 1
    assert soon[0].fingerprint == "abc"


def test_load_returns_empty_for_missing(tmp_path: Path) -> None:
    p = tmp_path / "missing.json"
    s = load(p)
    assert isinstance(s, State)
    assert s.deployments == []


def test_load_returns_empty_for_corrupt(tmp_path: Path) -> None:
    p = tmp_path / "state.json"
    p.write_text("{not valid json")
    s = load(p)
    assert s.deployments == []
