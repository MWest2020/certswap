# Init certswap — tasks

Numbered, grouped by milestone. Each milestone is shippable on its own;
later milestones build on earlier ones but do not regress them.

## M0: scaffold

- [ ] 0.1 — `uv init` with Python 3.12, src/ layout, `pyproject.toml`
- [ ] 0.2 — Add runtime deps: `typer`, `rich`, `cryptography`, `pydantic` v2, `httpx`
- [ ] 0.3 — Add dev deps: `pytest`, `pytest-mock`, `mypy`, `ruff`
- [ ] 0.4 — `kubernetes` is intentionally deferred to M4 — do not add yet
- [ ] 0.5 — Configure `mypy --strict` in `pyproject.toml`
- [ ] 0.6 — Configure `ruff` (sensible defaults, line length 100)
- [ ] 0.7 — `uv run check` recipe in README: ruff + mypy + pytest
- [ ] 0.8 — README skeleton: install via `uv tool install .`, usage examples
- [ ] 0.9 — `.gitignore` for Python + `.certswap/` user state

## M1: ingest + inspect

- [ ] 1.1 — `models.py`: `CertBundle`, `SourceFormat`, `Plan`, `ApplyResult`, `VerifyResult` (pydantic v2)
- [ ] 1.2 — Pydantic custom types wrapping `x509.Certificate` and `PrivateKey`
- [ ] 1.3 — `ingest/detect.py`: format detection by content (magic bytes, PEM headers, ZIP/TAR/GZIP signatures, PKCS#7 OID)
- [ ] 1.4 — `ingest/pem.py`: parse PEM bundle (any order, mixed leaf/chain/key)
- [ ] 1.5 — `ingest/pfx.py`: PKCS#12 via cryptography; shell-out to `openssl pkcs12 -legacy` when MAC algo is RC2-40-CBC
- [ ] 1.6 — `ingest/pkcs7.py`: .p7b parsing
- [ ] 1.7 — `ingest/archive.py`: extract zip/tar to tempdir, recursive re-dispatch
- [ ] 1.8 — `ingest/separate.py`: directory or explicit `--cert/--key/--chain`
- [ ] 1.9 — Password sources: `--password-stdin`, `--password-env VAR`. Never on CLI argv
- [ ] 1.10 — `core/chain.py`: order chain leaf→root, detect gaps
- [ ] 1.11 — `core/chain.py`: AIA-walk to complete chain (`--fetch-intermediates`)
- [ ] 1.12 — `core/validation.py`: key↔cert modulus / public-key match
- [ ] 1.13 — `core/validation.py`: chain verify against trust store
- [ ] 1.14 — `core/trust.py`: Linux trust store discovery (Debian, RHEL, Alpine paths)
- [ ] 1.15 — `commands/inspect.py`: rich tabulated output; `--json` mode
- [ ] 1.16 — `cli.py`: wire `inspect`
- [ ] 1.17 — Test fixtures: self-signed CA + leaf via a one-off generator script
- [ ] 1.18 — Test fixture: Sectigo-style PFX (legacy MAC) — either real or synthesized
- [ ] 1.19 — Tests per ingest format, per validation rule

## M2: local driver + plan/apply skeleton

- [ ] 2.1 — `drivers/base.py`: `EgressDriver` Protocol, `TargetContext`, shared helpers
- [ ] 2.2 — `drivers/local.py`: `plan`, `apply`, `verify`
- [ ] 2.3 — `commands/plan.py`, `commands/apply.py`, `commands/verify.py`: dispatch to driver by name
- [ ] 2.4 — `evidence.py`: write `evidence.json` (pydantic-modeled) + `evidence.md`
- [ ] 2.5 — `state.py`: append-on-apply to `~/.certswap/state.json`
- [ ] 2.6 — Confirmation prompt; `--yes` skip; `--json` implies `--yes`
- [ ] 2.7 — Global flags wiring: `--evidence-dir`, `--json`, `-v/--verbose`
- [ ] 2.8 — Exit code map enforced centrally (see design.md §exit codes)
- [ ] 2.9 — Tests: local driver round-trip (apply + verify + state update)

## M3: ssh driver

- [ ] 3.1 — `drivers/ssh.py`: shell-out wrappers `_ssh(host, cmd)` and `_scp(src, host, dst)`
- [ ] 3.2 — Plan: connect check, target paths writable, disk space, pre-check command
- [ ] 3.3 — Plan: read existing certs on target paths, diff expiry / SANs / issuer
- [ ] 3.4 — Apply: scp to `/tmp/` tempfile on remote, then atomic `mv` to dest
- [ ] 3.5 — Apply: backup existing to `<dest>.bak-<UTC-ts>` before overwrite
- [ ] 3.6 — Apply: `chmod` + `chown` per flags; defaults 0644 cert / 0600 key
- [ ] 3.7 — Apply: reload command + post-check; on post-check fail, restore backup
- [ ] 3.8 — `--combined-dest` writes leaf+key+chain in a single PEM
- [ ] 3.9 — Tests: mock `subprocess.run`; verify command construction, ordering, rollback

## M4: k8s driver (no ArgoCD)

- [ ] 4.1 — Add `kubernetes` dependency
- [ ] 4.2 — `drivers/k8s.py`: plan — verify cluster context matches `--context`, namespace exists, secret state, cert-manager Certificate, Ingress hosts vs leaf SANs
- [ ] 4.3 — Plan abort on host mismatch unless `--allow-host-mismatch`
- [ ] 4.4 — Apply: delete cert-manager Certificate (if present), strip Ingress `cert-manager.io/cluster-issuer` annotation (unless `--keep-cert-manager`), delete + create secret
- [ ] 4.5 — Verify: re-fetch secret, check annotation absence, check secret matches bundle fingerprint
- [ ] 4.6 — Tests: kubernetes client mocked

## M4b: ArgoCD layer

- [ ] 4b.1 — Detect ArgoCD `Application` by `--argocd-app <name>`
- [ ] 4b.2 — Plan: report `syncPolicy.automated`, `selfHeal`, `ignoreDifferences`, `syncOptions`
- [ ] 4b.3 — Apply pre-step: disable automated sync, patch `ignoreDifferences`, set `syncOptions.RespectIgnoreDifferences=true`, `selfHeal=false`
- [ ] 4b.4 — Apply post-step: re-enable automated sync; `selfHeal` stays `false`
- [ ] 4b.5 — Verify (60s wait): annotation not restored, Certificate not re-created, secret intact
- [ ] 4b.6 — Tests

## M5: proxmox driver

- [ ] 5.1 — `drivers/proxmox.py`: thin wrapper composing the ssh driver
- [ ] 5.2 — Defaults: `/etc/pve/local/pveproxy-ssl.pem` (combined) + `/etc/pve/local/pveproxy-ssl.key`
- [ ] 5.3 — Reload: `systemctl restart pveproxy`
- [ ] 5.4 — Post-check: `curl -fsS https://localhost:8006`
- [ ] 5.5 — Tests

## M6: state + upcoming

- [ ] 6.1 — `state.py`: dedupe on append by `(driver, identifier, fingerprint)`
- [ ] 6.2 — `commands/upcoming.py`: filter `not_after < now + 60d`, sort ascending
- [ ] 6.3 — `--json` for `upcoming`
- [ ] 6.4 — Tests

## Release

- [ ] R.1 — Tag `v0.1.0`
- [ ] R.2 — `uv tool install git+https://github.com/MWest2020/certswap` works end-to-end
- [ ] R.3 — Optional: publish to PyPI (only if Mark wants a `pip install` surface)
