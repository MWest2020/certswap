from __future__ import annotations

from pathlib import Path

from certswap.ingest import ingest
from certswap.ingest.pfx import openssl_version, parse_pfx
from certswap.models import SourceFormat


def test_parse_pfx_modern_no_legacy(pfx_bundle: Path) -> None:
    cb = parse_pfx(pfx_bundle, password=b"hunter2")
    assert cb.source_format == SourceFormat.PFX
    assert cb.needs_legacy_mode is False
    assert cb.subject_cn() == "test.certswap.example"
    assert len(cb.chain) == 1


def test_parse_pfx_legacy_fallback(legacy_pfx_bundle: Path) -> None:
    """An openssl-`-legacy`-exported PFX must parse correctly via *either* path.

    Whether ``needs_legacy_mode`` ends up True depends on whether the
    installed ``cryptography`` version transparently handles the legacy
    MAC; both outcomes are acceptable as long as the bundle round-trips.
    """
    cb = parse_pfx(legacy_pfx_bundle, password=b"hunter2")
    assert cb.source_format == SourceFormat.PFX
    assert cb.subject_cn() == "test.certswap.example"
    assert len(cb.chain) >= 1
    assert isinstance(cb.needs_legacy_mode, bool)


def test_ingest_dispatches_to_pfx(pfx_bundle: Path) -> None:
    cb = ingest(pfx_bundle, password=b"hunter2")
    assert cb.source_format == SourceFormat.PFX


def test_openssl_version_returns_string_or_none() -> None:
    v = openssl_version()
    assert v is None or v.lower().startswith("openssl")
