from __future__ import annotations

from pathlib import Path

import pytest

from certswap.ingest.detect import FormatDetectionError, detect_format
from certswap.models import SourceFormat


def test_detect_pem(pem_bundle: Path) -> None:
    assert detect_format(pem_bundle) == SourceFormat.PEM_BUNDLE


def test_detect_pfx(pfx_bundle: Path) -> None:
    assert detect_format(pfx_bundle) == SourceFormat.PFX


def test_detect_zip(zip_bundle: Path) -> None:
    assert detect_format(zip_bundle) == SourceFormat.ARCHIVE


def test_detect_tar_gz(tar_gz_bundle: Path) -> None:
    assert detect_format(tar_gz_bundle) == SourceFormat.ARCHIVE


def test_detect_directory(separate_files_dir: Path) -> None:
    assert detect_format(separate_files_dir) == SourceFormat.SEPARATE_FILES


def test_detect_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    with pytest.raises(FormatDetectionError, match="empty file"):
        detect_format(empty)


def test_detect_unknown(tmp_path: Path) -> None:
    blob = tmp_path / "random.bin"
    blob.write_bytes(b"not a cert\nnot a chain\n")
    with pytest.raises(FormatDetectionError, match="unrecognized"):
        detect_format(blob)


def test_detect_p7b_by_extension(tmp_path: Path) -> None:
    # ASN.1 SEQUENCE start; we use the .p7b suffix to disambiguate from PFX.
    p7 = tmp_path / "chain.p7b"
    p7.write_bytes(b"\x30\x82\x01\x00")
    assert detect_format(p7) == SourceFormat.PKCS7
