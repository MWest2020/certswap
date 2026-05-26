# certswap — design

## Architecture

```
┌─────────────────────┐
│ INGEST              │
│   detect.py         │   format by content, not extension
│   pfx.py            │   PKCS#12 (incl. legacy MAC via openssl shell-out)
│   pem.py            │   PEM bundle (any order, mixed)
│   pkcs7.py          │   .p7b
│   archive.py        │   zip/tar → tempdir → re-dispatch
│   separate.py       │   loose files via --cert/--key/--chain or dir
└──────────┬──────────┘
           │ parses to
           ▼
┌─────────────────────┐
│ CORE                │
│   models.CertBundle │   canonical internal model
│   chain.py          │   order, gap-detect, AIA-walk
│   validation.py     │   key↔cert, SAN match, chain verify
│   trust.py          │   Linux trust store discovery
└──────────┬──────────┘
           │ feeds
           ▼
┌─────────────────────┐
│ EGRESS (drivers)    │
│   base.py           │   Protocol + helpers
│   local.py          │   filesystem
│   ssh.py            │   ssh/scp shell-out
│   k8s.py            │   kubernetes client (+ ArgoCD layer in M4b)
│   proxmox.py        │   ssh.py wrapper with PVE defaults
└──────────┬──────────┘
           │ emits
           ▼
┌─────────────────────┐
│ EVIDENCE / STATE    │
│   evidence.py       │   evidence.json + evidence.md per apply
│   state.py          │   ~/.certswap/state.json for `upcoming`
└─────────────────────┘
```

## CertBundle (canonical model)

```python
class SourceFormat(StrEnum):
    PFX = "pfx"
    PEM_BUNDLE = "pem_bundle"
    SEPARATE_FILES = "separate_files"
    PKCS7 = "pkcs7"
    ARCHIVE = "archive"      # intermediate only; resolved before reaching core

class CertBundle(BaseModel):
    leaf: x509.Certificate           # via pydantic custom type
    private_key: PrivateKey          # idem
    chain: list[x509.Certificate]    # ordered leaf→root, EXCLUDING leaf
    source_format: SourceFormat
    source_path: Path
    needs_legacy_mode: bool          # true when openssl -legacy was required

    # Methods
    def fingerprint_sha256(self) -> str: ...
    def sans(self) -> list[str]: ...
    def issuer_cn(self) -> str: ...
    def not_after(self) -> datetime: ...
    def is_chain_complete(self, trust_store: Path) -> bool: ...
    def key_matches_cert(self) -> bool: ...
    def to_pem_fullchain(self) -> bytes: ...
    def to_pem_key(self) -> bytes: ...
    def canonical_hash(self) -> str: # SHA256 over canonical PEM serialization
```

Pydantic custom types wrap `cryptography` objects so the model can serialize
to dict/json for evidence files. The `canonical_hash` is computed over a
deterministic PEM serialization, not the original input file — two functionally
identical bundles delivered in different formats must hash the same.

## Driver protocol

```python
class TargetContext(BaseModel):
    driver: str
    options: dict[str, Any]   # driver-specific; validated inside the driver

class PlanStep(BaseModel):
    description: str
    before: str | None        # observed target state
    would_do: str             # what apply would do

class Plan(BaseModel):
    driver: str
    steps: list[PlanStep]
    warnings: list[str]
    blockers: list[str]       # non-empty → apply is refused

class StepResult(BaseModel):
    description: str
    before: str | None
    after: str | None
    duration_ms: int
    ok: bool
    error: str | None

class ApplyResult(BaseModel):
    driver: str
    steps: list[StepResult]
    exit_code: int
    verify: VerifyResult | None

class CheckResult(BaseModel):
    name: str
    ok: bool
    detail: str | None

class VerifyResult(BaseModel):
    ok: bool
    checks: list[CheckResult]

class EgressDriver(Protocol):
    name: str

    def plan(self, bundle: CertBundle, ctx: TargetContext) -> Plan: ...
    def apply(self, bundle: CertBundle, ctx: TargetContext) -> ApplyResult: ...
    def verify(self, ctx: TargetContext) -> VerifyResult: ...
```

Driver-specific flags live as Typer sub-options under the chosen `--target`,
not on the global command, so `cli.py` stays free of driver knowledge.

## Exit codes

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | Success                                                              |
| 1    | Unhandled exception (bug)                                            |
| 2    | CLI usage error (Typer default)                                      |
| 10   | Validation failed (key/cert mismatch, SAN mismatch, chain incomplete)|
| 20   | Target drift: live state ≠ planned pre-state (idempotent retry ok)   |
| 30   | Ingest failed: unrecognized format, wrong password, corrupt file     |
| 40   | Remote unreachable: ssh / k8s API / etc. connection failed           |
| 50   | Apply failed mid-flight (partial state — see evidence dir)           |
| 60   | Verify failed post-apply                                             |

`cli.py` owns the mapping; commands raise typed exceptions and the top-level
handler translates to exit codes. Never `sys.exit()` from deep in the call
tree.

## File structure

```
src/certswap/
├── __init__.py
├── cli.py                  Typer app entrypoint
├── models.py               CertBundle, Plan, ApplyResult, ...
├── ingest/
│   ├── __init__.py
│   ├── detect.py
│   ├── pfx.py
│   ├── pem.py
│   ├── pkcs7.py
│   ├── archive.py
│   └── separate.py
├── core/
│   ├── chain.py
│   ├── validation.py
│   └── trust.py
├── drivers/
│   ├── __init__.py
│   ├── base.py
│   ├── local.py
│   ├── ssh.py
│   ├── k8s.py
│   └── proxmox.py
├── evidence.py
├── state.py
└── commands/
    ├── inspect.py
    ├── plan.py
    ├── apply.py
    ├── verify.py
    └── upcoming.py
tests/
└── ... (mirrors src layout)
openspec/
└── changes/
    └── init-certswap/
        ├── proposal.md
        ├── tasks.md
        └── design.md
```

Hard rule: ≤200 lines per source file. If a file grows past that, split.
Likely split candidates: `drivers/k8s.py` → `drivers/k8s/__init__.py` +
`secret.py` + `argocd.py` once M4b lands.

## Key abstractions

### Ingest dispatch

`ingest.detect.detect_format(path) -> SourceFormat`. Opens the file and
inspects content. Order:

1. Magic bytes: PKCS#12, PKCS#7, ZIP (`PK\x03\x04`), TAR (`ustar`), GZIP (`1f 8b`)
2. PEM headers: `-----BEGIN ...-----`
3. Directory: dispatch to `separate.py`
4. Fallback: refuse with exit 30

Extension is a tiebreaker only, never authoritative — customers and CAs
rename files freely.

Archive formats extract to a `tempfile.TemporaryDirectory` and re-dispatch.
The outer caller never sees archive state.

### Chain completion

`core.chain.complete_chain(bundle, *, fetch=False) -> CertBundle`:

1. Order what we have by `issuer` ↔ `subject` matching.
2. If a gap exists and `fetch=True`: fetch the AIA `caIssuers` URL via
   `httpx.get()` (synchronous), parse the result (DER or PEM), insert,
   repeat.
3. Stop when the current cert is self-signed (root reached) or no AIA
   extension is present.
4. Failure is non-fatal at `inspect` time (emit warning), fatal at `plan`
   time unless `--allow-incomplete-chain`.

### Trust store

`core.trust.discover() -> Path` returns the first existing path:

```
/etc/ssl/certs/ca-certificates.crt    Debian/Ubuntu
/etc/pki/tls/certs/ca-bundle.crt      RHEL/Fedora
/etc/ssl/cert.pem                     Alpine
```

Override via `--trust-store <path>`. macOS keychain is explicitly out of
scope for v1.

### PKCS#12 legacy

Sectigo's PFX files use RC2-40-CBC for the MAC, which OpenSSL 3+ rejects by
default. Strategy:

1. Try `cryptography.hazmat.primitives.serialization.pkcs12.load_pkcs12()`.
2. On `InvalidKey` / unsupported MAC, shell-out to:
   ```
   openssl pkcs12 -legacy -in <pfx> -nodes -password env:CERTSWAP_PFX_PASS
   ```
3. Set `CertBundle.needs_legacy_mode = True`.
4. Record `openssl --version` output in `evidence.json` so the audit trail
   includes which binary parsed the bundle.

### SSH approach

All remote ops go through `subprocess.run(["ssh", host, *args])` and
`subprocess.run(["scp", src, f"{host}:{dst}"])`. No paramiko. `host` is
always a name; `~/.ssh/config` resolves ProxyJump, IdentityFile,
ControlMaster, etc. No `--ssh-key` flag in v1.

Every command printed in plan output is the exact command that would run.
Reproducible by hand: copy, paste in a terminal, see the same effect.

### Evidence

One directory per apply:

```
<evidence-dir>/<UTC-iso-timestamp>-<driver>-<identifier>/
    evidence.json
    evidence.md
```

`identifier` is driver-defined:

- `local`: basename of `--dest`
- `ssh`: `<host>:<dest-path>`
- `k8s`: `<namespace>/<secret>@<context>`
- `proxmox`: `<host>:pveproxy`

`evidence.json` schema is a pydantic model in `evidence.py` for type-checking
and forward compatibility. `evidence.md` is a human render of the same data:
context paragraph, actions chronologically with before/after, verification
checklist, renewal info (expiry + agenda hint), driver-specific rollback
instructions.

### State

`~/.certswap/state.json`:

```json
{
  "deployments": [
    {
      "timestamp": "2026-05-26T14:23:00Z",
      "target": "k8s",
      "identifier": "nextcloud/tls-cert@homelab",
      "fingerprint": "SHA256:abc...",
      "not_after": "2027-01-15T00:00:00Z",
      "evidence_dir": "~/.certswap/evidence/2026-05-26-..."
    }
  ]
}
```

Append-on-apply with dedupe by `(target, identifier, fingerprint)` — a
re-apply of the same bundle doesn't create a duplicate entry. `upcoming`
filters `not_after < now + 60d`, sorts ascending, renders. No locking
(single-user tool).

## Confirmation flow

`apply` renders the Plan, then prompts `Proceed? [y/N]`. `--yes` skips.
`--json` implies `--yes` for non-interactive scripting. There is no
"interactive prompt over JSON output" mode — that combination is rejected
with exit 2.

## Testing strategy

- `tests/fixtures/` holds real bundles: a small generator script produces
  a self-signed CA + leaf + chain in every supported format.
- One real Sectigo-shaped PFX (synthesized to use legacy MAC) for the
  shell-out path.
- Unit tests per ingest format, per validation rule, per driver helper.
- Driver tests mock `subprocess.run` for ssh; use `kubernetes` client
  fakes for k8s.
- One round-trip integration test per driver against a local target:
  `local` uses tmpdir; `ssh` targets `127.0.0.1` via a test alias in CI;
  `k8s` uses kind or an in-process fake.
