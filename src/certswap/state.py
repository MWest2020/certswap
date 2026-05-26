"""User-level deployment state: ``~/.certswap/state.json``.

Append-on-apply with dedupe by ``(driver, identifier, fingerprint)`` so
that re-applying an unchanged bundle does not create duplicate entries.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class StateEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    target: str
    identifier: str
    fingerprint: str
    not_after: datetime
    evidence_dir: str


class State(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deployments: list[StateEntry] = Field(default_factory=list)


def default_state_path() -> Path:
    return Path.home() / ".certswap" / "state.json"


def load(path: Path | None = None) -> State:
    state_path = path or default_state_path()
    if not state_path.is_file():
        return State()
    raw = state_path.read_text()
    try:
        return State.model_validate_json(raw)
    except ValueError:
        # Corrupt state file — return empty rather than failing the apply.
        # The user can investigate ~/.certswap/state.json by hand.
        return State()


def _dedupe_key(entry: StateEntry) -> tuple[str, str, str]:
    return (entry.target, entry.identifier, entry.fingerprint)


def append(entry: StateEntry, path: Path | None = None) -> State:
    state_path = path or default_state_path()
    state = load(state_path)
    new_key = _dedupe_key(entry)
    state.deployments = [e for e in state.deployments if _dedupe_key(e) != new_key]
    state.deployments.append(entry)
    _atomic_write(state_path, state.model_dump_json(indent=2))
    return state


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".certswap-", dir=path.parent)
    try:
        with open(fd, "w") as fh:
            fh.write(content)
        Path(tmp).replace(path)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise


def upcoming(within_days: int = 60, state: State | None = None) -> list[StateEntry]:
    """Return state entries whose certs expire within ``within_days`` days,
    sorted by expiry ascending.
    """
    state = state or load()
    deadline = datetime.now(UTC).astimezone(UTC)
    upcoming_entries = [
        e
        for e in state.deployments
        if (e.not_after - deadline).days <= within_days
    ]
    upcoming_entries.sort(key=lambda e: e.not_after)
    return upcoming_entries
