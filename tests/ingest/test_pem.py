from __future__ import annotations

from pathlib import Path

import pytest

from certswap.ingest import ingest
from certswap.ingest.pem import PemParseError, parse_pem
from certswap.models import SourceFormat


def test_parse_pem_extracts_leaf_key_and_chain(pem_bundle: Path) -> None:
    cb = parse_pem(pem_bundle)
    assert cb.source_format == SourceFormat.PEM_BUNDLE
    assert cb.source_path == pem_bundle
    assert cb.subject_cn() == "test.certswap.example"
    assert "test.certswap.example" in cb.sans()
    assert len(cb.chain) == 1
    assert cb.needs_legacy_mode is False


def test_parse_pem_leaf_only_chain_empty(pem_bundle_leaf_only: Path) -> None:
    cb = parse_pem(pem_bundle_leaf_only)
    assert cb.chain == []
    assert cb.subject_cn() == "test.certswap.example"


def test_parse_pem_rejects_no_key(tmp_path: Path, pem_bundle: Path) -> None:
    data = pem_bundle.read_bytes()
    cert_only = data.split(b"-----BEGIN PRIVATE")[0]
    bad = tmp_path / "no-key.pem"
    bad.write_bytes(cert_only)
    with pytest.raises(PemParseError, match="no private key"):
        parse_pem(bad)


def test_ingest_dispatches_to_pem(pem_bundle: Path) -> None:
    cb = ingest(pem_bundle)
    assert cb.source_format == SourceFormat.PEM_BUNDLE


def test_parse_pem_keyless_when_key_not_required(cert_only_pem: Path) -> None:
    cb = parse_pem(cert_only_pem, require_key=False)
    assert cb.private_key is None
    assert cb.has_key() is False
    assert cb.subject_cn() == "test.certswap.example"


def test_keyless_bundle_refuses_key_serialization(cert_only_pem: Path) -> None:
    cb = parse_pem(cert_only_pem, require_key=False)
    with pytest.raises(ValueError, match="no private key"):
        cb.to_pem_key()


def test_ingest_keyless_pem(cert_only_pem: Path) -> None:
    cb = ingest(cert_only_pem, require_key=False)
    assert cb.private_key is None
    assert cb.source_format == SourceFormat.PEM_BUNDLE


def test_ingest_cert_only_pem_with_explicit_key(
    cert_only_pem: Path, separate_files_dir: Path
) -> None:
    # CA-delivered fullchain (no embedded key) + --key must combine the two.
    cb = ingest(cert_only_pem, key_path=separate_files_dir / "privkey.pem")
    assert cb.private_key is not None
    assert cb.subject_cn() == "test.certswap.example"
