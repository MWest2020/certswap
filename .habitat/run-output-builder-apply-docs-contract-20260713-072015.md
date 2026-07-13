# Habitat builder — apply-docs-contract

_run_id builder-apply-docs-contract-20260713-072015 · verdict ok · 2026-07-13T07:22:23Z_

---

Done. Here's the run report.

## Run report — builder / `apply-docs-contract`

**Branch:** `habitat/builder/apply-docs-contract` (started branch; no new branch created — per task 1.1 the harness manages branches/push).
**Commit:** `e04d843 docs: apply handbook docs contract`

### What I did (in scope, nothing else)

| Task | Status | Notes |
|------|--------|-------|
| 1.1 Work on given branch | ✅ | Stayed on `habitat/builder/apply-docs-contract`. |
| 2.1 `docs/` structure + migration/stubs | ✅ | Repo had no `docs/` → minimum viable created. No existing loose docs to migrate, so no stubs needed. |
| 2.2 Front matter (migrated-without-review → `status: draft` + `last_reviewed`) | ✅ | Both pages: `status: draft`, `last_reviewed: 2026-07-13`. No `owner` field. |
| 2.3 `docs/index.md` | ✅ | One-paragraph overview, status note, link to README, link to reference section. |
| 2.4 `.mcp.json` template | ✅ (pre-seeded) | Already committed in the seed (`9633250`) with `url: "TODO-change-3"` — matches template, left untouched. |
| 3.1 Self-check | ✅ | Only allowed submap (`reference/`) carries markdown + root `index.md`; every page has YAML front matter; English only; no empty dirs; README kept & linked, not replaced. |
| 4.1 Open PR | ⚠️ **blocked** | `gh` is not installed and the session is non-interactive with no auth/upstream. I cannot push or open the PR. The harness owns push/PR per task 1.1. |

### Files
- `docs/index.md` (new)
- `docs/reference/cli.md` (new — CLI commands, drivers, input formats, output/state, exit codes, migrated from README)
- `openspec/changes/apply-docs-contract/tasks.md` (checkboxes updated)

### PR to open (title + body ready for harness/Mark)

**Title:** `docs: apply handbook docs contract`

**Body:**
> Applies the handbook docs contract (Westmarch `add-docs-contract`) to certswap.
>
> Contract points applied:
> - [x] `docs/` created per structure (`index.md` + `reference/`); empty dirs omitted; minimum viable (`index.md` + one reference page)
> - [x] YAML front matter on every page: `status` + `last_reviewed`, **no** `owner`
> - [x] Migrated-without-review → `status: draft`, `last_reviewed: 2026-07-13`
> - [x] One language per repo (English)
> - [x] README kept; `docs/index.md` links to it, does not replace it
> - [x] `.mcp.json` present with template + `TODO-change-3` placeholder (seeded)
> - [x] No changes outside `docs/` (no CLAUDE.md / `.claude/agents/` / CI edits)
>
> **Stops here — Mark merges.**

**Stopping now — I do not merge, and PR creation requires the harness to push the branch.**
