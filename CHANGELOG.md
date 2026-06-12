# Changelog

All notable changes to certswap. Dates are ISO (YYYY-MM-DD).

## [0.3.0] — 2026-06-12

### Added
- **`--ingress-host`** (plan/apply k8s, requires `--ingress`): attach a
  new host to an existing ingress — rule (backend copied from the first
  rule) + TLS entry for `--secret`, idempotently. Built for the
  "customer vanity domain with an externally delivered cert on a shared
  GitOps cluster" workflow, replacing the error-prone manual
  edit-ingress-plus-ignoreDifferences procedure. Behavior:
  - SAN validation applies to the **new host only**; existing hosts on a
    shared ingress keep their own TLS entries.
  - Blocked in combination with `--keep-cert-manager`: ingress-shim
    issues a certificate for every TLS entry on an annotated ingress and
    would overwrite the swapped secret.
  - The annotation strip warns which other hosts lose automatic LE
    renewal (move them to a separate annotated ingress, e.g. a redirect
    ingress, before their certs expire).
  - With `--argocd-app`, the ingress `ignoreDifferences` entry covers
    `/spec` as well as `/metadata/annotations` (entries merged by
    resource identity, pointers unioned). Documented trade-off:
    chart-side ingress changes stop propagating until the entry is
    removed.
  - `verify` gains an "ingress serves host" check.
- New modules to honor the 200-line cap: `drivers/_k8s_ingress.py`
  (ingress planning), `drivers/_k8s_live_ingress.py` (live ingress
  mutations), `drivers/_k8s_argo_meta.py` (pure Argo helpers).

### Tests
- 118 tests (was 112): host-attach plan/apply/verify, SAN scoping,
  keep-cert-manager conflict, ignoreDifferences pointer merging.

## [0.2.0] — 2026-06-12

### Added (packaging / community release)
- PyPI packaging metadata: SPDX license, classifiers, keywords, project
  URLs; version bumped to 0.2.0. Official EUPL-1.2 text added as
  `LICENSE`.
- GitHub Actions: `ci.yml` (ruff + mypy + pytest on 3.12/3.13, locked
  sync) and `release.yml` (tag-triggered build + PyPI trusted publishing,
  with a tag↔`__version__` consistency check).
- `CONTRIBUTING.md` with the quality gate, 200-line cap, fake-injection
  testing convention, and release procedure.
- README: positioning intro (out-of-band TLS replacement for
  GitOps-managed and mixed infrastructure), PyPI install instructions,
  disambiguation note vs the archived `pivotal-cf/certswap`.

### Fixed
- `ingest`: an explicit `--key` was silently ignored (exit 30 before
  this release) when the cert file was a PEM bundle without an embedded
  key — the common "CA-delivered fullchain + separately generated key"
  case. The two are now combined via the separate-files path.
  (`ingest/__init__.py`)

The sections below are the production-hardening of the ArgoCD
coordination layer plus keyless inspection, prompted by an internal
review for team (Conduction) use.

### Changed
- **ArgoCD: original sync policy is now saved and restored.** Before, the
  swap re-enabled automated sync with a hardcoded `{prune: true,
  selfHeal: false}` — silently enabling pruning on apps that never had it
  (pruning can delete cluster resources not in git) and enabling auto-sync
  on apps that were manual. Now the pre-swap `spec.syncPolicy.automated`
  is JSON-saved to the `certswap.io/saved-automated-sync` annotation on
  the Application (crash-recoverable from cluster state) and restored
  afterwards with only `selfHeal` forced off. A crashed swap keeps the
  oldest saved policy; a second `disable` never overwrites it.
  (`drivers/_k8s_live_argo.py`, `drivers/_k8s_argo.py`, protocol rename
  `re_enable_argo_sync_no_selfheal` → `restore_argo_sync`)
- **k8s secret swap is now a single in-place replace** (PUT, create on
  404) instead of delete + create — there is no longer a window in which
  the secret does not exist. Fallback to delete+create only when the
  existing secret has a different (immutable) type. (`drivers/_k8s_live.py`,
  `drivers/k8s.py`)
- `ignoreDifferences` / `syncOptions` patches are **idempotent**: repeated
  swaps no longer accumulate duplicate entries.
  (`drivers/_k8s_live_argo.py`)

### Added
- **Managed-Application detection.** `plan`/`apply k8s --argocd-app` now
  blocks when the Application is owned by an ApplicationSet
  (ownerReference) or a parent app (app-of-apps tracking label/annotation),
  since the owning controller would revert certswap's patches — the
  `ignoreDifferences` belongs in git in that topology. New flag
  `--argocd-force-managed` overrides with a plan warning.
  (`drivers/_k8s_argo.py`, `drivers/_k8s_options.py`, plan/apply k8s CLI)
- **`inspect` works on cert-only CA deliveries.** `CertBundle.private_key`
  is now optional; ingest accepts `require_key=False` (used only by
  `inspect`), directory ingest falls back to a single unambiguous
  top-level `*.crt`/`*.pem` as the leaf (CA deliveries name it
  `<domain>.crt`), and the renderers report "no private key in bundle"
  instead of erroring with exit 30. Deployment commands (`plan`/`apply`)
  still require the key. (`models.py`, `ingest/*`, `commands/inspect.py`,
  `commands/_inspect_view.py`)

### Tests
- New `tests/drivers/test_k8s_live_argo.py`: covers the live merge-patch
  logic (previously untested) with a stub `CustomObjectsApi` implementing
  RFC 7386 semantics — policy save/restore incl. prune preservation,
  not-automated-stays-off, crashed-swap annotation handling, idempotency,
  and managed-by detection.
- Managed-app blocker/override tests, keyless ingest/inspect tests.
- Suite: 91 → 111 tests, ruff + mypy clean, all source files ≤ 200 lines.

## [0.1.0] — 2026-06-12

Initial release: ingest (PFX/PEM/PKCS#7/archive/separate), validation,
drivers (local/ssh/k8s+ArgoCD/proxmox), evidence trail, state tracking,
`upcoming` command.
