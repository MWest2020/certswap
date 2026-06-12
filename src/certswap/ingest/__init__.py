"""Top-level ingest dispatcher.

Routes a path to the right format-specific parser. Archive formats are
extracted and recursively re-dispatched.
"""

from __future__ import annotations

from pathlib import Path

from certswap.ingest.archive import parse_archive
from certswap.ingest.detect import FormatDetectionError, detect_format
from certswap.ingest.pem import parse_pem
from certswap.ingest.pfx import parse_pfx
from certswap.ingest.pkcs7 import Pkcs7ParseError, parse_pkcs7_bundle, parse_pkcs7_certs
from certswap.ingest.separate import parse_directory, parse_separate
from certswap.models import CertBundle, SourceFormat


class IngestError(ValueError):
    """Raised when no parser can handle the given input."""


def ingest(
    path: Path,
    *,
    password: bytes | None = None,
    key_path: Path | None = None,
    chain_path: Path | None = None,
    key_password: bytes | None = None,
    require_key: bool = True,
) -> CertBundle:
    """Detect ``path``'s format and parse it into a CertBundle.

    Optional parameters:

    * ``password`` — PFX/PKCS#12 password (also applied to the key when
      the leaf format does not include the key — i.e. PKCS#7).
    * ``key_path``, ``chain_path`` — explicit overrides for the
      ``separate`` and ``pkcs7`` formats.
    * ``key_password`` — password for the private key when distinct from
      the bundle password.
    * ``require_key`` — when False, cert-only input parses into a keyless
      bundle. Read-only flows (``inspect``) use this; deployment flows
      must keep the default.
    """
    if path.is_dir():
        return parse_directory(path, key_password or password, require_key=require_key)

    fmt = detect_format(path)
    effective_key_password = key_password if key_password is not None else password

    if fmt == SourceFormat.PEM_BUNDLE:
        bundle = parse_pem(path, require_key=require_key and key_path is None)
        if bundle.private_key is None and key_path is not None:
            # Cert-only PEM (e.g. a CA-delivered fullchain) + explicit --key.
            return parse_separate(
                cert_path=path,
                key_path=key_path,
                chain_path=chain_path,
                key_password=effective_key_password,
            )
        return bundle
    if fmt == SourceFormat.PFX:
        try:
            return parse_pfx(path, password)
        except ValueError as exc:
            if key_path is not None:
                try:
                    return parse_pkcs7_bundle(
                        path, key_path=key_path, key_password=effective_key_password
                    )
                except Pkcs7ParseError:
                    pass
            raise IngestError(f"could not parse {path} as PFX: {exc}") from exc
    if fmt == SourceFormat.PKCS7:
        if key_path is None and require_key:
            raise IngestError(
                f"PKCS#7 file {path} contains no private key; pass --key to ingest"
            )
        return parse_pkcs7_bundle(
            path, key_path=key_path, key_password=effective_key_password
        )
    if fmt == SourceFormat.ARCHIVE:
        return parse_archive(
            path,
            redispatch=lambda inner: ingest(
                inner,
                password=password,
                key_path=key_path,
                chain_path=chain_path,
                key_password=key_password,
                require_key=require_key,
            ),
        )
    if fmt == SourceFormat.SEPARATE_FILES:
        if key_path is None and require_key:
            raise IngestError(
                f"separate-files ingest of {path} needs an explicit --key"
            )
        return parse_separate(
            cert_path=path,
            key_path=key_path,
            chain_path=chain_path,
            key_password=effective_key_password,
        )
    raise IngestError(f"unhandled source format: {fmt}")  # pragma: no cover


__all__ = [
    "FormatDetectionError",
    "IngestError",
    "Pkcs7ParseError",
    "ingest",
    "parse_pkcs7_certs",
]
