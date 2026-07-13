---
status: draft
last_reviewed: 2026-07-13
---

# certswap docs

certswap is a deterministic TLS bundle swap CLI: it ingests a TLS bundle in any
common format (PFX, PEM bundle, separate files, PKCS#7, zip/tar archive),
validates it, and deploys it to a target — a Kubernetes secret, an SSH-reachable
VM, a local directory, or a Proxmox host — with a structured evidence trail per
swap. For the project overview, install instructions, and design rationale, see
the [README](../README.md); this `docs/` tree does not replace it.

**Status:** these pages were migrated from the README without an independent
content review, so they are marked `status: draft`.

## Sections

- [Reference](reference/cli.md) — CLI commands, drivers, input formats, and exit
  codes.
