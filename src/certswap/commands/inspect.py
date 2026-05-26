"""`certswap inspect` — show what's in a bundle. No target involved."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from rich.console import Console
from rich.table import Table

from certswap.core import trust as trust_mod
from certswap.core.chain import chain_is_complete, complete_chain
from certswap.core.validation import key_matches_cert, verify_chain
from certswap.ingest import IngestError, ingest
from certswap.models import CertBundle

console = Console()


def _resolve_password(
    password_env: str | None, password_stdin: bool
) -> bytes | None:
    if password_env and password_stdin:
        raise typer.BadParameter(
            "use either --password-env or --password-stdin, not both"
        )
    if password_env:
        value = os.environ.get(password_env)
        if value is None:
            raise typer.BadParameter(
                f"env var {password_env!r} is not set"
            )
        return value.encode("utf-8")
    if password_stdin:
        return sys.stdin.read().rstrip("\n").encode("utf-8")
    return None


def _key_type(bundle: CertBundle) -> str:
    key = bundle.private_key
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"EC {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448"
    return type(key).__name__


def _render_rich(
    bundle: CertBundle,
    *,
    chain_complete: bool,
    key_ok: bool,
    chain_verified: bool | None,
) -> None:
    src_label = f"{bundle.source_path} ({bundle.source_format.value}"
    if bundle.needs_legacy_mode:
        src_label += ", legacy mode required"
    src_label += ")"
    console.print(f"[bold]Source:[/bold] {src_label}")

    leaf_table = Table(title="Leaf", show_header=False, box=None, pad_edge=False)
    leaf_table.add_row("Subject CN", bundle.subject_cn() or "—")
    leaf_table.add_row("SANs", ", ".join(bundle.sans()) or "—")
    leaf_table.add_row("Issuer", bundle.issuer_cn())
    not_before = bundle.not_before().strftime("%Y-%m-%d")
    not_after = bundle.not_after().strftime("%Y-%m-%d")
    leaf_table.add_row(
        "Valid",
        f"{not_before} → {not_after} ({bundle.days_remaining()} days remaining)",
    )
    leaf_table.add_row("Fingerprint", "SHA256:" + bundle.fingerprint_sha256())
    leaf_table.add_row("Key type", _key_type(bundle))
    console.print(leaf_table)

    chain_table = Table(title="Chain", show_header=False, box=None, pad_edge=False)
    if bundle.chain:
        for idx, cert in enumerate(bundle.chain):
            attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if attrs:
                raw = attrs[0].value
                cn = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
            else:
                cn = cert.subject.rfc4514_string()
            chain_table.add_row(f"[{idx}]", cn)
    else:
        chain_table.add_row("(no intermediates)", "")
    chain_table.add_row(
        "Complete",
        "yes" if chain_complete else "no — consider --fetch-intermediates",
    )
    console.print(chain_table)

    key_table = Table(title="Key", show_header=False, box=None, pad_edge=False)
    key_table.add_row("Matches leaf", "yes" if key_ok else "[red]NO[/red]")
    if chain_verified is not None:
        key_table.add_row(
            "Verified against trust store",
            "yes" if chain_verified else "no",
        )
    console.print(key_table)


def _render_json(
    bundle: CertBundle,
    *,
    chain_complete: bool,
    key_ok: bool,
    chain_verified: bool | None,
) -> None:
    payload: dict[str, Any] = {
        "source": {
            "path": str(bundle.source_path),
            "format": bundle.source_format.value,
            "needs_legacy_mode": bundle.needs_legacy_mode,
        },
        "leaf": {
            "subject_cn": bundle.subject_cn(),
            "sans": bundle.sans(),
            "issuer_cn": bundle.issuer_cn(),
            "not_before": bundle.not_before().isoformat(),
            "not_after": bundle.not_after().isoformat(),
            "days_remaining": bundle.days_remaining(),
            "fingerprint_sha256": bundle.fingerprint_sha256(),
            "key_type": _key_type(bundle),
        },
        "chain": {
            "length": len(bundle.chain),
            "complete": chain_complete,
        },
        "validation": {
            "key_matches_leaf": key_ok,
            "chain_verified": chain_verified,
        },
        "generated_at": datetime.now(UTC).isoformat(),
    }
    typer.echo(json.dumps(payload, indent=2))


def inspect_command(
    bundle_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=True, readable=True)
    ],
    password_env: Annotated[
        str | None, typer.Option("--password-env", help="Env var holding bundle password")
    ] = None,
    password_stdin: Annotated[
        bool, typer.Option("--password-stdin", help="Read bundle password from stdin")
    ] = False,
    fetch_intermediates: Annotated[
        bool,
        typer.Option(
            "--fetch-intermediates",
            help="Complete the chain via the AIA extension",
        ),
    ] = False,
    trust_store: Annotated[
        Path | None,
        typer.Option(
            "--trust-store",
            help="Override system trust store path",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON")
    ] = False,
    key: Annotated[
        Path | None,
        typer.Option(
            "--key",
            help="Private key path (for PKCS#7 or separate-file ingest)",
            exists=True,
            readable=True,
        ),
    ] = None,
    chain: Annotated[
        Path | None,
        typer.Option(
            "--chain",
            help="Chain path (separate-file ingest only)",
            exists=True,
            readable=True,
        ),
    ] = None,
) -> None:
    """Show the contents of a TLS bundle without performing any target work."""
    password = _resolve_password(password_env, password_stdin)
    try:
        bundle = ingest(
            bundle_path,
            password=password,
            key_path=key,
            chain_path=chain,
        )
    except IngestError as exc:
        typer.echo(f"ingest failed: {exc}", err=True)
        raise typer.Exit(code=30) from exc
    except ValueError as exc:
        # cryptography raises ValueError for parse / decryption failures
        # below the IngestError layer (e.g. wrong password, malformed DER).
        typer.echo(f"ingest failed: {exc}", err=True)
        raise typer.Exit(code=30) from exc

    if fetch_intermediates:
        bundle = complete_chain(bundle, fetch=True)

    chain_complete = chain_is_complete(bundle.chain)
    key_ok = key_matches_cert(bundle.private_key, bundle.leaf)

    chain_verified: bool | None = None
    if trust_store is not None or _trust_store_available():
        store_path = trust_store or trust_mod.discover()
        chain_verified = verify_chain(bundle, store_path)

    if json_out:
        _render_json(
            bundle,
            chain_complete=chain_complete,
            key_ok=key_ok,
            chain_verified=chain_verified,
        )
    else:
        _render_rich(
            bundle,
            chain_complete=chain_complete,
            key_ok=key_ok,
            chain_verified=chain_verified,
        )

    if not key_ok:
        raise typer.Exit(code=10)


def _trust_store_available() -> bool:
    try:
        trust_mod.discover()
    except trust_mod.TrustStoreNotFound:
        return False
    return True
