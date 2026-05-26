"""PKCS#7 (.p7b / .p7c) ingest.

PKCS#7 bundles contain only certificates (no private key). They are
useful for delivering the chain. The accompanying private key must
be supplied separately and combined via ``parse_pkcs7_bundle``.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from certswap.ingest.pem import _pick_leaf
from certswap.models import CertBundle, SourceFormat


class Pkcs7ParseError(ValueError):
    """Raised when a PKCS#7 file cannot be parsed."""


def _load_certs(data: bytes, path: Path) -> list[x509.Certificate]:
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            certs = pkcs7.load_pem_pkcs7_certificates(data)
        else:
            certs = pkcs7.load_der_pkcs7_certificates(data)
    except ValueError as exc:
        raise Pkcs7ParseError(f"PKCS#7 parse failed at {path}: {exc}") from exc
    return list(certs)


def parse_pkcs7_certs(path: Path) -> list[bytes]:
    """Return the DER-encoded certificates contained in a PKCS#7 file."""
    data = path.read_bytes()
    certs = _load_certs(data, path)
    return [c.public_bytes(serialization.Encoding.DER) for c in certs]


def parse_pkcs7_bundle(
    path: Path, *, key_path: Path, key_password: bytes | None
) -> CertBundle:
    """Combine a PKCS#7 cert blob with an external private key file."""
    data = path.read_bytes()
    certs = _load_certs(data, path)
    if not certs:
        raise Pkcs7ParseError(f"PKCS#7 file at {path} contained no certificates")
    leaf, chain = _pick_leaf(certs)

    key_bytes = key_path.read_bytes()
    if key_bytes.lstrip().startswith(b"-----BEGIN"):
        private_key = serialization.load_pem_private_key(key_bytes, password=key_password)
    else:
        private_key = serialization.load_der_private_key(key_bytes, password=key_password)

    return CertBundle(
        leaf=leaf,
        private_key=private_key,
        chain=chain,
        source_format=SourceFormat.PKCS7,
        source_path=path,
        needs_legacy_mode=False,
    )
