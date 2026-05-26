from __future__ import annotations

from pathlib import Path

from certswap.ingest import ingest
from certswap.ingest.pkcs7 import parse_pkcs7_bundle
from certswap.models import SourceFormat


def test_parse_pkcs7_bundle_with_external_key(
    pkcs7_chain_with_key: tuple[Path, Path],
) -> None:
    p7, key = pkcs7_chain_with_key
    cb = parse_pkcs7_bundle(p7, key_path=key, key_password=None)
    assert cb.source_format == SourceFormat.PKCS7
    assert cb.subject_cn() == "test.certswap.example"
    assert len(cb.chain) == 1


def test_ingest_pkcs7_requires_key_path(
    pkcs7_chain_with_key: tuple[Path, Path],
) -> None:
    import pytest

    from certswap.ingest import IngestError

    p7, _ = pkcs7_chain_with_key
    with pytest.raises(IngestError, match=r"pass --key"):
        ingest(p7)


def test_ingest_pkcs7_with_key(pkcs7_chain_with_key: tuple[Path, Path]) -> None:
    p7, key = pkcs7_chain_with_key
    cb = ingest(p7, key_path=key)
    assert cb.source_format == SourceFormat.PKCS7
