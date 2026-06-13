# certswap

Deterministic TLS bundle swap CLI.

Take a TLS bundle in any common format (PFX, PEM bundle, separate files,
PKCS#7, zip/tar archive), validate it, and deploy it to a target — a
Kubernetes secret, an SSH-reachable VM, a local directory, or a Proxmox
host — with a structured evidence trail per swap.

Built for the operational reality no other tool covers: a CA or customer
hands you a bundle out-of-band and it has to land safely on
GitOps-managed or mixed infrastructure. ACME clients automate
issuance-driven renewal; cert-manager owns the in-cluster path; certswap
handles everything that arrives by hand — with an ArgoCD-safe swap that
existing tooling only documents as a manual procedure.

Not related to the archived `pivotal-cf/certswap` (a Go tool for
swapping system trust stores).

## Install

Requires Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```sh
uv tool install certswap        # from PyPI (first release pending)
uv tool install git+https://github.com/MWest2020/certswap   # latest main
```

For local development:

```sh
git clone git@github.com:MWest2020/certswap.git
cd certswap
uv sync --dev
uv run ruff check . && uv run mypy src && uv run pytest
```

Tests are in-process (a test CA/intermediate/leaf is generated per session —
no binary fixtures in the repo). The `smoke` marker covers end-to-end CLI
round-trips (ingest → apply → verify) across input formats; run just those
with `uv run pytest -m smoke`.

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

Drivers: `local`, `ssh`, `k8s` (with optional ArgoCD coordination), `proxmox`.
All commands accept `--json` for machine-readable output; `apply` writes an
evidence dir under `~/.certswap/evidence/`; deployments are tracked in
`~/.certswap/state.json` for `upcoming`.

## What it does

Concretely, this is one command per target for the parts of TLS-renewal
that normally cost an afternoon and a postmortem:

- Customers / CAs deliver bundles in random formats — every command
  normalises PFX (incl. Sectigo's RC2-40-CBC legacy MAC, via
  `openssl pkcs12 -legacy` shell-out), PEM bundles, PKCS#7, archives,
  and separate-file layouts to one canonical `CertBundle`. `inspect`
  also accepts cert-only CA deliveries (no private key yet) — deployment
  commands keep requiring the key.
- Leaf-only bundles can be AIA-walked into a complete chain at inspect
  time (`inspect --fetch-intermediates`).
- Key↔cert mismatches and SAN/host mismatches are caught at `plan`,
  not at deployment.
- On Kubernetes, `apply k8s` deletes the cert-manager Certificate that
  produced the secret and strips the
  `cert-manager.io/cluster-issuer` annotation, then replaces the
  `kubernetes.io/tls` secret in place (a single PUT — no window in
  which the secret is absent). With `--argocd-app`, the Application's
  automated-sync policy is saved to an annotation and disabled,
  `RespectIgnoreDifferences=true` and `ignoreDifferences` entries are
  patched in (idempotently), and after the swap the saved policy is
  restored with `selfHeal` forced off — because `selfHeal` ignores
  `ignoreDifferences`. `prune` and the rest of the policy come back
  exactly as they were; an app that wasn't auto-syncing stays that way.
- Applications owned by an ApplicationSet or a parent app (app-of-apps)
  are detected and block the plan: the owning controller would revert
  certswap's patches, so the `ignoreDifferences` belongs in git there.
  `--argocd-force-managed` overrides with a warning.
- `--ingress-host` attaches a new host (rule + TLS entry) to an existing
  ingress — the "customer domain with externally delivered cert on a
  shared GitOps cluster" case. The cert-manager annotation is stripped
  (ingress-shim would otherwise overwrite the swapped secret; the plan
  warns which other hosts lose automatic renewal), and with
  `--argocd-app` the ingress `/spec` is protected via
  `ignoreDifferences`. Note: chart-side ingress changes stop syncing
  until that entry is removed.
- On a VM, `apply ssh` uses your `~/.ssh/config`, scp-uploads to a
  random `/tmp/` file, atomic-mv's into place, chmod/chown's, runs
  your reload command, post-checks, and restores backups on failure.
- On Proxmox, `apply proxmox` is `apply ssh` with the pveproxy
  defaults baked in.
- Every `apply` writes both `evidence.json` (pydantic-modeled, for
  machines) and `evidence.md` (for the next human who'll renew this
  cert a year from now).

## Exit codes

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | Success                                                              |
| 10   | Validation failed (plan blocked, host/key mismatch)                  |
| 30   | Ingest failed (bad format, wrong password)                           |
| 50   | Apply failed mid-flight (incl. remote unreachable during apply)      |
| 60   | Verify failed post-apply (incl. target drift)                        |

## License

EUPL-1.2.
