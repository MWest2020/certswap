from __future__ import annotations

from pathlib import Path

import pytest

from certswap.core import trust as trust_mod


def test_discover_real_or_skipped() -> None:
    """If no real Linux trust store is available, the discover call must
    raise; otherwise it must return a file path that exists.
    """
    try:
        path = trust_mod.discover()
    except trust_mod.TrustStoreNotFound:
        pytest.skip("no Linux trust store on this host")
    assert isinstance(path, Path)
    assert path.is_file()
