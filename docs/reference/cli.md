---
status: draft
last_reviewed: 2026-07-13
---

# CLI reference

Reference for the `certswap` command line. Migrated from the
[README](../../README.md); consult the README for narrative context and the
[CHANGELOG](../../CHANGELOG.md) for version history.

## Commands

```sh
certswap inspect <bundle>                                # show bundle contents (key optional)
certswap plan local   <bundle> --dest <dir>
certswap apply local  <bundle> --dest <dir>
certswap verify local --dest <dir>
certswap plan ssh     <bundle> --host <h> --cert-dest /etc/nginx/tls/x.pem --key-dest /etc/nginx/tls/x.key
certswap apply ssh    <bundle> --host <h> --cert-dest ... --key-dest ... --reload "nginx -s reload"
certswap plan k8s     <bundle> --namespace ns --secret tls --context homelab --ingress app
certswap apply k8s    <bundle> --namespace ns --secret tls --argocd-app my-app
certswap apply k8s    <bundle> --namespace ns --secret tls --ingress app --ingress-host www.example.org --argocd-app my-app
certswap apply proxmox <bundle> --host pve-node
certswap upcoming --within-days 60
```

Top-level commands:

- `inspect` — show bundle contents (a private key is optional; `inspect` also
  accepts cert-only CA deliveries).
- `plan <driver>` — validate a swap without applying it.
- `apply <driver>` — perform the swap and write an evidence directory.
- `verify <driver>` — check the target after an apply.
- `upcoming` — list tracked deployments approaching expiry.

Global options:

- `--version` — print the version and exit.

## Drivers

`local`, `ssh`, `k8s` (with optional ArgoCD coordination), and `proxmox`. Each
driver is available under `plan` and `apply`; `verify` supports `local`.

## Input formats

`inspect` and the deployment commands normalise the following to one canonical
bundle:

- PFX / PKCS#12 (including Sectigo's RC2-40-CBC legacy MAC, via
  `openssl pkcs12 -legacy`)
- PEM bundles
- PKCS#7
- zip / tar archives
- separate-file layouts (cert, key, chain)

Leaf-only bundles can be AIA-walked into a complete chain with
`inspect --fetch-intermediates`. Deployment commands always require the private
key.

## Output and state

- All commands accept `--json` for machine-readable output.
- `apply` writes an evidence directory under `~/.certswap/evidence/`, containing
  both `evidence.json` (pydantic-modeled) and `evidence.md` (human-readable).
- Deployments are tracked in `~/.certswap/state.json`, which `upcoming` reads.

## Exit codes

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | Success                                                              |
| 10   | Validation failed (plan blocked, host/key mismatch)                  |
| 30   | Ingest failed (bad format, wrong password)                           |
| 50   | Apply failed mid-flight (incl. remote unreachable during apply)      |
| 60   | Verify failed post-apply (incl. target drift)                        |
