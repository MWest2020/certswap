# certswap

Deterministic TLS bundle swap CLI.

Take a TLS bundle in any common format (PFX, PEM bundle, separate files,
PKCS#7, zip/tar archive), validate it, and deploy it to a target — a
Kubernetes secret, an SSH-reachable VM, a local directory, or a Proxmox
host — with a structured evidence trail per swap.

Single-user tool, personal infrastructure use.

## Status

Pre-release. Implementation driven by
[`openspec/changes/init-certswap/`](openspec/changes/init-certswap/).
See `proposal.md`, `tasks.md`, `design.md` for scope and architecture.

## Install

Requires Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```sh
uv tool install git+https://github.com/MWest2020/certswap
```

For local development:

```sh
git clone git@github.com:MWest2020/certswap.git
cd certswap
uv sync --dev
```

## Commands (planned)

```sh
certswap inspect <bundle>                          # show bundle contents
certswap plan <bundle> --target <driver> [opts]    # dry-run
certswap apply <bundle> --target <driver> [opts]   # execute, write evidence
certswap verify --target <driver> [opts]           # post-check
certswap upcoming                                  # what expires within 60d
```

Targets: `local`, `ssh`, `k8s`, `proxmox`.

## Development

```sh
uv sync --dev
uv run ruff check .
uv run mypy src
uv run pytest
```

## License

EUPL-1.2.
