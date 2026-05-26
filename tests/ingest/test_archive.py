from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest

from certswap.ingest import ingest
from certswap.ingest.archive import ArchiveError, parse_archive
from certswap.models import SourceFormat


def test_zip_archive_redispatches_to_pem(zip_bundle: Path) -> None:
    cb = ingest(zip_bundle)
    assert cb.source_format == SourceFormat.PEM_BUNDLE
    assert cb.subject_cn() == "test.certswap.example"


def test_tar_gz_archive_redispatches_to_separate(tar_gz_bundle: Path) -> None:
    cb = ingest(tar_gz_bundle)
    assert cb.source_format == SourceFormat.SEPARATE_FILES
    assert cb.subject_cn() == "test.certswap.example"


def test_zip_rejects_traversal(tmp_path: Path) -> None:
    bad_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../escape.pem", b"-----BEGIN CERTIFICATE-----\n")
    with pytest.raises(ArchiveError, match="escapes target dir"):
        parse_archive(bad_zip, redispatch=lambda _p: pytest.fail("should not reach"))


def test_tar_rejects_symlink(tmp_path: Path) -> None:
    bad_tar = tmp_path / "evil.tar"
    with tarfile.open(bad_tar, "w") as tf:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    with pytest.raises(ArchiveError, match="link"):
        parse_archive(bad_tar, redispatch=lambda _p: pytest.fail("should not reach"))
