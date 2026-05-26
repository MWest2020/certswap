"""Archive ingest: extract zip/tar/gz/tar.gz then recursively re-dispatch."""

from __future__ import annotations

import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path

from certswap.models import CertBundle


class ArchiveError(ValueError):
    """Raised when an archive cannot be extracted or contains no bundle."""


def _safe_zip_extract(path: Path, dest: Path) -> None:
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(path) as zf:
        for member in zf.namelist():
            target = (dest / member).resolve()
            if not target.is_relative_to(dest_resolved):
                raise ArchiveError(f"zip entry escapes target dir: {member!r}")
        zf.extractall(dest)  # noqa: S202 -- members vetted above


def _safe_tar_extract(path: Path, dest: Path) -> None:
    # tarfile's auto-detection mode handles plain tar + every common
    # compression we accept (.gz, .tgz, .bz2, .xz). Keeping the open mode
    # constant avoids the Literal-overload juggling mypy would otherwise
    # impose.
    dest_resolved = dest.resolve()
    with tarfile.open(path, "r:*") as tf:
        members = tf.getmembers()
        for m in members:
            target = (dest / m.name).resolve()
            if not target.is_relative_to(dest_resolved):
                raise ArchiveError(f"tar entry escapes target dir: {m.name!r}")
            if m.islnk() or m.issym():
                raise ArchiveError(f"tar entry is a link, refused: {m.name!r}")
        tf.extractall(dest, members=members, filter="data")


def _looks_like_zip(path: Path) -> bool:
    with path.open("rb") as fh:
        head = fh.read(4)
    return head[:2] == b"PK"


def parse_archive(
    path: Path,
    *,
    redispatch: Callable[[Path], CertBundle],
) -> CertBundle:
    """Extract ``path`` to a tempdir, then call ``redispatch`` on the result.

    The redispatch callable is the top-level ``ingest`` dispatcher, passed
    in to avoid an import cycle. It is invoked on the extracted directory;
    when the directory contains a single nested bundle (e.g. one PFX), the
    dispatcher handles that case via ``detect_format`` recursion.
    """
    with ExitStack() as stack:
        tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="certswap-")))
        if _looks_like_zip(path):
            _safe_zip_extract(path, tmp)
        else:
            _safe_tar_extract(path, tmp)

        # If exactly one file landed at the root and is itself a bundle,
        # hand that file directly to redispatch. Otherwise, hand the dir.
        entries = [p for p in tmp.iterdir() if not p.name.startswith(".")]
        if len(entries) == 1 and entries[0].is_file():
            return redispatch(entries[0])
        return redispatch(tmp)
    raise ArchiveError(f"unreachable: archive extraction at {path}")
