"""PKCS#12 (.pfx / .p12) ingest.

Strategy:

1. Try ``cryptography.hazmat.primitives.serialization.pkcs12.load_pkcs12``.
2. On failure that looks like a legacy MAC (Sectigo RC2-40-CBC), shell-out
   to ``openssl pkcs12 -legacy ...`` and re-parse the PEM output.
3. The ``needs_legacy_mode`` flag is set on the returned bundle so the
   evidence trail records which path was taken.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12

from certswap.ingest.pem import _pick_leaf, _split_pem_blocks
from certswap.models import CertBundle, SourceFormat


class PfxParseError(ValueError):
    """Raised when a PKCS#12 file cannot be parsed via either path."""


_LEGACY_HINTS = (
    "mac",
    "rc2",
    "legacy",
    "invalid",
    "unsupported",
    "wrong",
)


def _looks_like_legacy_failure(message: str) -> bool:
    lowered = message.lower()
    return any(hint in lowered for hint in _LEGACY_HINTS)


def _via_cryptography(
    data: bytes, password: bytes | None
) -> tuple[x509.Certificate, PrivateKeyTypes, list[x509.Certificate]] | None:
    try:
        result = pkcs12.load_pkcs12(data, password)
    except (ValueError, TypeError) as exc:
        if _looks_like_legacy_failure(str(exc)):
            return None
        raise PfxParseError(f"PKCS#12 parse failed: {exc}") from exc
    if result.cert is None or result.cert.certificate is None:
        raise PfxParseError("PKCS#12 contains no certificate")
    if result.key is None:
        raise PfxParseError("PKCS#12 contains no private key")
    chain = [entry.certificate for entry in (result.additional_certs or [])]
    return result.cert.certificate, result.key, chain


def _via_openssl_legacy(
    path: Path, password: bytes | None
) -> tuple[x509.Certificate, PrivateKeyTypes, list[x509.Certificate]]:
    if shutil.which("openssl") is None:
        raise PfxParseError(
            "PKCS#12 needs legacy mode but `openssl` is not on PATH"
        )
    proc = subprocess.run(
        [
            "openssl",
            "pkcs12",
            "-legacy",
            "-in",
            str(path),
            "-nodes",
            "-passin",
            "stdin",
        ],
        input=(password or b"") + b"\n",
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise PfxParseError(f"openssl pkcs12 -legacy failed: {stderr}")

    pem_blob = proc.stdout
    blocks = _split_pem_blocks(pem_blob)
    certs: list[x509.Certificate] = []
    private_key: PrivateKeyTypes | None = None
    for block in blocks:
        if b"-----BEGIN CERTIFICATE-----" in block:
            certs.append(x509.load_pem_x509_certificate(block))
        elif b"PRIVATE KEY-----" in block:
            if private_key is not None:
                raise PfxParseError("legacy PFX contained multiple private keys")
            private_key = serialization.load_pem_private_key(block, password=None)
    if private_key is None or not certs:
        raise PfxParseError("legacy PFX output missing key or certificate(s)")
    leaf, chain = _pick_leaf(certs)
    return leaf, private_key, chain


def openssl_version() -> str | None:
    """Return ``openssl --version`` output, or None if openssl is missing.

    Recorded in evidence.json when the legacy fallback path is taken.
    """
    if shutil.which("openssl") is None:
        return None
    try:
        proc = subprocess.run(
            ["openssl", "version"], capture_output=True, check=True, text=True
        )
    except subprocess.CalledProcessError:
        return None
    return re.sub(r"\s+", " ", proc.stdout.strip())


def parse_pfx(path: Path, password: bytes | None) -> CertBundle:
    """Parse a PKCS#12 (.pfx / .p12) file into a CertBundle."""
    data = path.read_bytes()
    parsed = _via_cryptography(data, password)
    if parsed is not None:
        leaf, key, chain = parsed
        needs_legacy = False
    else:
        leaf, key, chain = _via_openssl_legacy(path, password)
        needs_legacy = True

    return CertBundle(
        leaf=leaf,
        private_key=key,
        chain=chain,
        source_format=SourceFormat.PFX,
        source_path=path,
        needs_legacy_mode=needs_legacy,
    )
