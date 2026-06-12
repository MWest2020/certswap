# Contributing

## Development setup

Requires Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```sh
git clone git@github.com:MWest2020/certswap.git
cd certswap
uv sync --dev
```

## Quality gate

Every change must pass all three before review; CI enforces the same:

```sh
uv run ruff check .
uv run mypy src
uv run pytest
```

## Conventions

- Every source file stays **≤ 200 lines** — split modules rather than
  growing them (see `drivers/_k8s_argo.py` vs `drivers/_k8s_live_argo.py`
  for the pattern).
- Drivers talk to the outside world through a Protocol facade
  (`drivers/_k8s_client.py`); tests inject fakes, never mock the
  kubernetes/ssh libraries directly.
- New behavior ships with tests in the same PR. Cluster-mutating logic
  needs coverage of the failure/rollback path, not just the happy path.
- Update `CHANGELOG.md` in the same commit as the change.
- Commit style: `fix:`/`feat:`/`refactor:`/`chore:` prefix, imperative
  mood.

## Releasing

1. Bump `version` in `pyproject.toml` **and** `__version__` in
   `src/certswap/__init__.py` (the release workflow rejects mismatches).
2. Add a dated CHANGELOG section.
3. Tag: `git tag v<version> && git push origin v<version>` — the
   `release.yml` workflow runs the quality gate, builds, and publishes
   to PyPI via trusted publishing.
