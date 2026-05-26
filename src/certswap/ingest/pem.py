"""PEM bundle parsing: leaf, key, and chain from a single mixed file."""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from certswap.models import CertBundle, SourceFormat


class PemParseError(ValueError):
    """Raised when a PEM bundle cannot be parsed into leaf/key/chain."""


def _split_pem_blocks(data: bytes) -> list[bytes]:
    blocks: list[bytes] = []
    buf: list[bytes] = []
    inside = False
    for line in data.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(b"-----BEGIN"):
            inside = True
            buf = [line]
        elif stripped.startswith(b"-----END"):
            buf.append(line)
            blocks.append(b"".join(buf))
            inside = False
            buf = []
        elif inside:
            buf.append(line)
    return blocks


def _is_cert_block(block: bytes) -> bool:
    return b"-----BEGIN CERTIFICATE-----" in block


def _is_key_block(block: bytes) -> bool:
    return b"PRIVATE KEY-----" in block


def _pick_leaf(certs: list[x509.Certificate]) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Identify the leaf cert (one whose subject is no other cert's issuer).

    Returns (leaf, remaining_chain_candidates).
    """
    if not certs:
        raise PemParseError("no certificates in PEM bundle")
    if len(certs) == 1:
        return certs[0], []
    issuer_subjects = {c.issuer.public_bytes() for c in certs}
    leaves = [c for c in certs if c.subject.public_bytes() not in issuer_subjects]
    if len(leaves) == 1:
        leaf = leaves[0]
    else:
        # Ambiguous — fall back to the first non-self-signed cert, then
        # the first cert. This mirrors what most operators expect when
        # the bundle is ill-formed but contains an obvious leaf.
        non_self = [c for c in certs if c.issuer.public_bytes() != c.subject.public_bytes()]
        leaf = non_self[0] if non_self else certs[0]
    rest = [c for c in certs if c is not leaf]
    return leaf, rest


def parse_pem(path: Path) -> CertBundle:
    """Parse a PEM bundle file containing at least a cert and a private key."""
    data = path.read_bytes()
    blocks = _split_pem_blocks(data)
    if not blocks:
        raise PemParseError(f"no PEM blocks found in {path}")

    certs: list[x509.Certificate] = []
    private_key: PrivateKeyTypes | None = None
    for block in blocks:
        if _is_cert_block(block):
            certs.append(x509.load_pem_x509_certificate(block))
        elif _is_key_block(block):
            if private_key is not None:
                raise PemParseError(f"multiple private keys in {path}")
            private_key = serialization.load_pem_private_key(block, password=None)

    if private_key is None:
        raise PemParseError(f"no private key in {path}")
    leaf, rest = _pick_leaf(certs)

    return CertBundle(
        leaf=leaf,
        private_key=private_key,
        chain=rest,
        source_format=SourceFormat.PEM_BUNDLE,
        source_path=path,
        needs_legacy_mode=False,
    )
