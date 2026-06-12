"""Rich + JSON renderers for ``certswap inspect``."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import typer
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from rich.console import Console
from rich.table import Table

from certswap.models import CertBundle

console = Console()


def key_type(bundle: CertBundle) -> str:
    key = bundle.private_key
    if key is None:
        return "absent"
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"EC {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448"
    return type(key).__name__


def render_rich(
    bundle: CertBundle,
    *,
    chain_complete: bool,
    key_ok: bool | None,
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
    leaf_table.add_row("Key type", key_type(bundle))
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
    if key_ok is None:
        key_table.add_row(
            "Matches leaf", "[yellow]no private key in bundle[/yellow]"
        )
    else:
        key_table.add_row("Matches leaf", "yes" if key_ok else "[red]NO[/red]")
    if chain_verified is not None:
        key_table.add_row(
            "Verified against trust store",
            "yes" if chain_verified else "no",
        )
    console.print(key_table)


def render_json(
    bundle: CertBundle,
    *,
    chain_complete: bool,
    key_ok: bool | None,
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
            "key_type": key_type(bundle),
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
