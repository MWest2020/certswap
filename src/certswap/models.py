"""Canonical internal data model: CertBundle + supporting types."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    PlainSerializer,
    PlainValidator,
)


class SourceFormat(StrEnum):
    PFX = "pfx"
    PEM_BUNDLE = "pem_bundle"
    SEPARATE_FILES = "separate_files"
    PKCS7 = "pkcs7"
    ARCHIVE = "archive"


def _validate_cert(value: Any) -> x509.Certificate:
    if isinstance(value, x509.Certificate):
        return value
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        if data.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    raise TypeError(f"cannot coerce {type(value).__name__} to x509.Certificate")


def _serialize_cert(value: x509.Certificate) -> str:
    return value.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _validate_key(value: Any) -> PrivateKeyTypes:
    if isinstance(value, (bytes, bytearray)):
        return serialization.load_pem_private_key(bytes(value), password=None)
    if hasattr(value, "private_bytes") and hasattr(value, "public_key"):
        # Duck-type: any cryptography private key. We trust the caller —
        # the protocol surface of PrivateKeyTypes is too broad to test.
        return value  # type: ignore[no-any-return]
    raise TypeError(f"cannot coerce {type(value).__name__} to PrivateKey")


def _serialize_key(value: PrivateKeyTypes) -> str:
    pem = value.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


X509Cert = Annotated[
    x509.Certificate,
    PlainValidator(_validate_cert),
    PlainSerializer(_serialize_cert, return_type=str),
]

PrivateKey = Annotated[
    PrivateKeyTypes,
    PlainValidator(_validate_key),
    PlainSerializer(_serialize_key, return_type=str),
]


class CertBundle(BaseModel):
    """Canonical internal representation of an ingested TLS bundle.

    Ordering invariant: ``chain`` is leaf→root and EXCLUDES ``leaf``.

    ``private_key`` may be None for read-only flows (``inspect`` of a
    cert-only CA delivery). Deployment flows require a key; ``to_pem_key``
    raises when it is absent.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    leaf: X509Cert
    private_key: PrivateKey | None
    chain: list[X509Cert]
    source_format: SourceFormat
    source_path: Path
    needs_legacy_mode: bool = False

    def fingerprint_sha256(self) -> str:
        der = self.leaf.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    def sans(self) -> list[str]:
        try:
            ext = self.leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            return []
        return [name.value for name in ext.value if hasattr(name, "value")]

    def issuer_cn(self) -> str:
        attrs = self.leaf.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not attrs:
            return self.leaf.issuer.rfc4514_string()
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", "replace")

    def subject_cn(self) -> str | None:
        attrs = self.leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not attrs:
            return None
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", "replace")

    def not_after(self) -> datetime:
        # cryptography>=42 prefers UTC-aware accessor.
        return self.leaf.not_valid_after_utc

    def not_before(self) -> datetime:
        return self.leaf.not_valid_before_utc

    def days_remaining(self) -> int:
        delta = self.not_after() - datetime.now(UTC)
        return delta.days

    def to_pem_fullchain(self) -> bytes:
        parts = [self.leaf, *self.chain]
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in parts)

    def has_key(self) -> bool:
        return self.private_key is not None

    def to_pem_key(self) -> bytes:
        if self.private_key is None:
            raise ValueError(
                f"bundle from {self.source_path} has no private key; "
                "deployment requires one (pass --key)"
            )
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def canonical_hash(self) -> str:
        """SHA256 over the canonical PEM serialization of leaf+chain+key.

        Stable across input formats — two functionally identical bundles
        delivered as PFX vs PEM hash to the same value.
        """
        h = hashlib.sha256()
        h.update(self.to_pem_fullchain())
        if self.private_key is not None:
            h.update(self.to_pem_key())
        return h.hexdigest()
