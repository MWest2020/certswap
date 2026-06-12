# Changelog

All notable changes to certswap. Dates are ISO (YYYY-MM-DD).

## [Unreleased] — 2026-06-12

Production-hardening of the ArgoCD coordination layer plus keyless
inspection, prompted by an internal review for team (Conduction) use.

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
