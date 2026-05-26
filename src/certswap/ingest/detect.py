"""Format detection by content — extension is a tiebreaker only.

Customers and CAs rename bundles freely; never trust the suffix to
decide the parser.
"""

from __future__ import annotations

from pathlib import Path

from certswap.models import SourceFormat


class FormatDetectionError(ValueError):
    """Raised when no supported format can be matched."""


_PEEK_BYTES = 4096


def _peek(path: Path) -> bytes:
    with path.open("rb") as fh:
        return fh.read(_PEEK_BYTES)


def _is_archive(head: bytes) -> bool:
    # ZIP: PK\x03\x04 (regular), PK\x05\x06 (empty), PK\x07\x08 (spanned)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return True
    # GZIP magic
    if head.startswith(b"\x1f\x8b"):
        return True
    # BZIP2 magic
    if head.startswith(b"BZh"):
        return True
    # XZ magic
    if head.startswith(b"\xfd7zXZ\x00"):
        return True
    # Plain tar: ustar marker at offset 257
    if len(head) >= 265 and head[257:262] == b"ustar":
        return True
    return False


def _is_pem(head: bytes) -> bool:
    return b"-----BEGIN" in head


def detect_format(path: Path) -> SourceFormat:
    """Inspect ``path`` and return the apparent source format.

    Directories are reported as ``SEPARATE_FILES``. Archives are reported
    generically; the ingest dispatcher extracts and re-detects. Binary
    blobs (ASN.1) are reported as PFX by default — the PFX parser
    transparently falls back to PKCS#7 when its parse fails.
    """
    if path.is_dir():
        return SourceFormat.SEPARATE_FILES
    if not path.is_file():
        raise FormatDetectionError(f"not a regular file or directory: {path}")
    head = _peek(path)
    if not head:
        raise FormatDetectionError(f"empty file: {path}")
    if _is_archive(head):
        return SourceFormat.ARCHIVE
    if _is_pem(head):
        return SourceFormat.PEM_BUNDLE
    # ASN.1 SEQUENCE (0x30) covers both PKCS#12 and PKCS#7. The dispatcher
    # tries PKCS#12 first and falls back to PKCS#7 on parse failure.
    if head[:1] == b"\x30":
        suffix = path.suffix.lower()
        if suffix in {".p7b", ".p7c"}:
            return SourceFormat.PKCS7
        return SourceFormat.PFX
    raise FormatDetectionError(
        f"unrecognized format at {path}: head={head[:16]!r}"
    )
