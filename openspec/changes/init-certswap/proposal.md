# Init certswap

## Scope

A Python 3.12+ CLI named `certswap` for taking a TLS bundle in any format
(PFX, PEM-bundle, separate files, PKCS#7, zip/tar) and deploying it to a
target (k8s secret, ssh-reachable VM, local directory, Proxmox host) with
validation up front and a structured evidence trail afterwards.

Single-user tool for Mark Westerweel. Personal infrastructure use.

## Why this exists

Today's renewal flow is manual and incident-prone:

- Customers and CAs deliver bundles in random formats
- Sectigo PFX needs OpenSSL `-legacy` for RC2-40-CBC MAC
- Bundles are often leaf-only — chain must be completed via AIA-walk
- Cert SANs must match target hosts; silent mismatches cause downtime
- Key↔cert modulus mismatch is a classic incident, currently hand-checked
- On k8s: cert-manager Certificate + Ingress annotation must go or your
  cert gets overwritten. ArgoCD `selfHeal` ignores `ignoreDifferences`
  entirely, so that needs to be disabled too
- On a VM: drop in the right path, the right perms, the right service reload
- No evidence trail of what was swapped when. A year later at renewal,
  nobody remembers what was actually done

`certswap` turns the swap into one deterministic command per target, with
structured before/after evidence per apply.

## Design overview

```
INGEST (polymorphic)            CORE              EGRESS (polymorphic)
────────────────────            ────              ────────────────────
pfx / p12                  ┐                  ┌── k8s-secret    (kubernetes API)
pem-bundle                 │                  │── ssh-file      (ssh + scp)
separate files (crt/key)   ├──→ CertBundle ──→├── local-dir     (filesystem)
pkcs#7 (.p7b)              │                  │── proxmox       (ssh-special)
zip / tar with loose files ┘                  └── (future: caddy/haproxy/...)
```

- `CertBundle` (pydantic v2) is the only internal representation
- Format detection by content, not extension
- One driver = one file under `src/certswap/drivers/<name>.py`
- Driver-specific flags via Typer sub-options; core CLI stays clean
- Idempotent apply: target state is read live, never memoized

## Commands

- `certswap inspect <bundle>` — show what's in the bundle, no target needed
- `certswap plan <bundle> --target <driver> [opts]` — dry-run
- `certswap apply <bundle> --target <driver> [opts]` — execute, write evidence
- `certswap verify --target <driver> [opts]` — post-check, no bundle needed
- `certswap upcoming` — what expires within 60 days

## Alternatives considered

### 1. Python vs Go vs Ansible

**Python (chosen).** The `cryptography` library is best-in-class for
PEM/PKCS parsing, validation, and chain handling. Pydantic v2 gives clean
models and validation for free. Typer + rich produces a CLI that is
pleasant without ceremony. Existing Python tooling in this account
(billbird-client, Gitsweeper) means reusable conventions.

**Go.** Tempting because it is the primary language here. But `crypto/x509`
is significantly more verbose for parsing odd real-world bundles, and
PKCS#12 legacy support either requires CGO into libcrypto or shell-out
anyway. Half the project would be re-implementing what `cryptography`
already provides for free.

**Ansible.** Plausible because the egress targets (k8s, ssh, local) are
all Ansible's home turf. But parsing and validating arbitrary inbound
bundles is awkward in YAML, the evidence trail would be unstructured,
and reusing this logic from another tool would be impossible. The right
direction is the inverse: Ansible can wrap `certswap` via `--json` later.

### 2. Driver pattern vs per-target CLI binaries

**Driver pattern (chosen).** One binary, one CLI surface, polymorphic
egress via a `Protocol`. Each driver is one ≤200-line file with the same
shape. Adding caddy, haproxy, or anything else later is trivial.

**Per-target binaries (`certswap-k8s`, `certswap-ssh`, ...).** Conceptually
clean but multiplies releases, packaging, documentation, and code duplication
for inspect/plan/apply. The shared work (parsing, validation, evidence) is
far larger than the driver-specific work.

### 3. Shell-out ssh vs paramiko

**Shell-out (chosen).** Respects `~/.ssh/config` automatically — ProxyJump,
IdentityFile, ControlMaster, agent forwarding all work without configuration
inside certswap. Every remote action is a literal `ssh <host> <cmd>` that
can be inspected, copy-pasted, and debugged by hand. Boring and auditable.

**Paramiko.** Re-implements ssh in Python. Doesn't read `ssh_config` by
default. ProxyJump support is fragile. Adds a heavy dependency for no win
on a single-user tool that already has a working ssh setup.

## Open decisions resolved before implementation

| Topic              | Decision                                                |
|--------------------|---------------------------------------------------------|
| Repo visibility    | Public on github.com/MWest2020/certswap                 |
| SSH key flow       | Only `~/.ssh/config` + agent. No `--ssh-key` flag in v1 |
| ArgoCD             | Split: M4 = k8s-only, M4b = ArgoCD layer on top         |
| PKCS#12 legacy     | Shell-out to `openssl pkcs12 -legacy`; version logged   |
| Trust store        | Linux paths only (`/etc/ssl/`, `/etc/pki/`); no macOS   |
| `inspect` output   | rich default + `--json` for scripting                   |

## Out of scope for v1

Web UI, renewal automation (only visibility via `upcoming`), cert generation
or signing, HSM / cloud KMS, SealedSecret / SOPS output, multi-target in a
single invocation, Helm chart edits, concurrency / locking.
