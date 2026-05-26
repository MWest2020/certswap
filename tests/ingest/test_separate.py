from __future__ import annotations

from pathlib import Path

from certswap.ingest import ingest
from certswap.ingest.separate import parse_directory
from certswap.models import SourceFormat


def test_parse_directory_letsencrypt_layout(separate_files_dir: Path) -> None:
    cb = parse_directory(separate_files_dir, key_password=None)
    assert cb.source_format == SourceFormat.SEPARATE_FILES
    assert cb.subject_cn() == "test.certswap.example"
    assert len(cb.chain) == 1


def test_ingest_dispatches_directory(separate_files_dir: Path) -> None:
    cb = ingest(separate_files_dir)
    assert cb.source_format == SourceFormat.SEPARATE_FILES
