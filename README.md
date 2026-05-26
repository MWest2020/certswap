# certswap

Deterministic TLS bundle swap CLI.

Take a TLS bundle in any common format (PFX, PEM bundle, separate files,
PKCS#7, zip/tar archive), validate it, and deploy it to a target — a
Kubernetes secret, an SSH-reachable VM, a local directory, or a Proxmox
host — with a structured evidence trail per swap.

Single-user tool, personal infrastructure use. v0.1.0.

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
uv run ruff check . && uv run mypy src && uv run pytest
```

## Commands

```sh
certswap inspect <bundle>                                # show bundle contents
certswap plan local   <bundle> --dest <dir>
certswap apply local  <bundle> --dest <dir>
certswap verify local --dest <dir>
certswap plan ssh     <bundle> --host <h> --cert-dest /etc/nginx/tls/x.pem --key-dest /etc/nginx/tls/x.key
certswap apply ssh    <bundle> --host <h> --cert-dest ... --key-dest ... --reload "nginx -s reload"
certswap plan k8s     <bundle> --namespace ns --secret tls --context homelab --ingress app
certswap apply k8s    <bundle> --namespace ns --secret tls --argocd-app my-app
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

- Customers / CAs deliver bundles in random formats — `inspect` and
  `ingest` normalise PFX (incl. Sectigo's RC2-40-CBC legacy MAC, via
  `openssl pkcs12 -legacy` shell-out), PEM bundles, PKCS#7, archives,
  and separate-file layouts to one canonical `CertBundle`.
- Leaf-only bundles get AIA-walked into a complete chain
  (`--fetch-intermediates`).
- Key↔cert mismatches and SAN/host mismatches are caught at `plan`,
  not at deployment.
- On Kubernetes, `apply k8s` deletes the cert-manager Certificate that
  produced the secret and strips the
  `cert-manager.io/cluster-issuer` annotation, then atomically swaps
  the `kubernetes.io/tls` secret. With `--argocd-app`, the ArgoCD
  Application is paused, `RespectIgnoreDifferences=true` is patched
  in, and `selfHeal=false` stays set after sync resumes — because
  `selfHeal` ignores `ignoreDifferences`.
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
| 20   | Target drift                                                         |
| 30   | Ingest failed (bad format, wrong password)                           |
| 40   | Remote unreachable                                                   |
| 50   | Apply failed mid-flight                                              |
| 60   | Verify failed post-apply                                             |

## License

EUPL-1.2.
