from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from certswap.core.validation import key_matches_cert, san_matches_host
from certswap.ingest.pem import parse_pem


def test_key_matches_cert_true_for_matching(pem_bundle: Path) -> None:
    cb = parse_pem(pem_bundle)
    assert key_matches_cert(cb.private_key, cb.leaf) is True


def test_key_matches_cert_false_for_mismatched(pem_bundle: Path) -> None:
    cb = parse_pem(pem_bundle)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert key_matches_cert(other_key, cb.leaf) is False


def test_san_match_exact(pem_bundle: Path) -> None:
    cb = parse_pem(pem_bundle)
    assert san_matches_host(cb, "test.certswap.example") is True
    assert san_matches_host(cb, "TEST.CERTSWAP.EXAMPLE") is True
    assert san_matches_host(cb, "other.example.com") is False


def test_san_wildcard_matches_one_label() -> None:
    # Synthetic bundle for wildcard test
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wild")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("*.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    from certswap.models import CertBundle, SourceFormat

    cb = CertBundle(
        leaf=cert,
        private_key=key,
        chain=[],
        source_format=SourceFormat.PEM_BUNDLE,
        source_path=Path("/dev/null"),
    )
    assert san_matches_host(cb, "foo.example.com") is True
    assert san_matches_host(cb, "example.com") is False
    assert san_matches_host(cb, "a.b.example.com") is False

    _ = replace  # silence unused-import linter
