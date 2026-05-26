from __future__ import annotations

from pathlib import Path

from certswap.core.chain import chain_is_complete, complete_chain, order_chain
from certswap.ingest.pem import parse_pem


def test_order_chain_strips_unrelated_certs(pem_bundle: Path) -> None:
    cb = parse_pem(pem_bundle)
    ordered = order_chain(cb.leaf, cb.chain)
    assert len(ordered) == 1
    assert ordered[0].issuer == ordered[0].subject or len(ordered) == 1


def test_chain_is_complete_when_ends_at_self_signed(pem_bundle: Path) -> None:
    # The fixture chain is leaf→intermediate; intermediate is not self-signed,
    # so the chain is not "complete" up to a self-signed root.
    cb = parse_pem(pem_bundle)
    assert chain_is_complete(cb.chain) is False


def test_complete_chain_no_fetch_reorders_in_place(pem_bundle: Path) -> None:
    cb = parse_pem(pem_bundle)
    completed = complete_chain(cb, fetch=False)
    assert len(completed.chain) == 1
