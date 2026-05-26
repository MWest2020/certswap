"""Ingest separate files: explicit --cert/--key/--chain, or a directory.

When given a directory, scans for common filenames:

* leaf cert:  ``fullchain.pem``, ``cert.pem``, ``leaf.pem``, ``server.crt``
* private key: ``privkey.pem``, ``key.pem``, ``server.key``
* chain (when separate from leaf): ``chain.pem``, ``intermediates.pem``,
  ``ca-bundle.pem``

If both ``fullchain.pem`` and ``cert.pem`` are present, ``fullchain.pem``
wins and ``chain.pem`` is ignored to avoid double-counting intermediates.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from certswap.ingest.pem import _pick_leaf, _split_pem_blocks
from certswap.models import CertBundle, SourceFormat


class SeparateFilesError(ValueError):
    """Raised when the input files do not constitute a complete bundle."""


_LEAF_CANDIDATES = ("fullchain.pem", "cert.pem", "leaf.pem", "server.crt", "tls.crt")
_KEY_CANDIDATES = ("privkey.pem", "key.pem", "server.key", "tls.key")
_CHAIN_CANDIDATES = ("chain.pem", "intermediates.pem", "ca-bundle.pem", "ca.crt")


def _first_existing(directory: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _load_certs_from_file(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    blocks = _split_pem_blocks(data)
    certs: list[x509.Certificate] = []
    for block in blocks:
        if b"-----BEGIN CERTIFICATE-----" in block:
            certs.append(x509.load_pem_x509_certificate(block))
    return certs


def _load_key(path: Path, password: bytes | None) -> PrivateKeyTypes:
    data = path.read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        return serialization.load_pem_private_key(data, password=password)
    return serialization.load_der_private_key(data, password=password)


def parse_separate(
    *,
    cert_path: Path,
    key_path: Path,
    chain_path: Path | None,
    key_password: bytes | None,
) -> CertBundle:
    """Combine an explicit cert + key (+ optional chain) into a CertBundle."""
    certs = _load_certs_from_file(cert_path)
    if not certs:
        raise SeparateFilesError(f"no certificates in {cert_path}")
    if chain_path is not None:
        certs.extend(_load_certs_from_file(chain_path))
    leaf, chain = _pick_leaf(certs)
    key = _load_key(key_path, key_password)

    return CertBundle(
        leaf=leaf,
        private_key=key,
        chain=chain,
        source_format=SourceFormat.SEPARATE_FILES,
        source_path=cert_path,
        needs_legacy_mode=False,
    )


def parse_directory(directory: Path, key_password: bytes | None) -> CertBundle:
    """Detect leaf/key/chain inside ``directory`` by common filenames."""
    if not directory.is_dir():
        raise SeparateFilesError(f"not a directory: {directory}")
    cert_path = _first_existing(directory, _LEAF_CANDIDATES)
    key_path = _first_existing(directory, _KEY_CANDIDATES)
    if cert_path is None:
        raise SeparateFilesError(
            f"no leaf certificate found in {directory}; "
            f"tried {', '.join(_LEAF_CANDIDATES)}"
        )
    if key_path is None:
        raise SeparateFilesError(
            f"no private key found in {directory}; "
            f"tried {', '.join(_KEY_CANDIDATES)}"
        )
    # If fullchain.pem is used, the chain candidates are redundant.
    chain_path: Path | None = None
    if cert_path.name != "fullchain.pem":
        chain_path = _first_existing(directory, _CHAIN_CANDIDATES)
    return parse_separate(
        cert_path=cert_path,
        key_path=key_path,
        chain_path=chain_path,
        key_password=key_password,
    )
