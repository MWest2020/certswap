from __future__ import annotations

from pathlib import Path

import pytest

from certswap.ingest import ingest
from certswap.ingest.separate import SeparateFilesError, parse_directory
from certswap.models import SourceFormat


def test_parse_directory_letsencrypt_layout(separate_files_dir: Path) -> None:
    cb = parse_directory(separate_files_dir, key_password=None)
    assert cb.source_format == SourceFormat.SEPARATE_FILES
    assert cb.subject_cn() == "test.certswap.example"
    assert len(cb.chain) == 1


def test_ingest_dispatches_directory(separate_files_dir: Path) -> None:
    cb = ingest(separate_files_dir)
    assert cb.source_format == SourceFormat.SEPARATE_FILES


def test_parse_directory_ca_delivery_without_key(ca_delivery_dir: Path) -> None:
    cb = parse_directory(ca_delivery_dir, key_password=None, require_key=False)
    assert cb.private_key is None
    assert cb.subject_cn() == "test.certswap.example"


def test_parse_directory_still_requires_key_by_default(ca_delivery_dir: Path) -> None:
    with pytest.raises(SeparateFilesError, match="no private key"):
        parse_directory(ca_delivery_dir, key_password=None)
