"""`certswap inspect` — show what's in a bundle. No target involved."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from certswap.commands._inspect_view import render_json, render_rich
from certswap.commands.common import load_bundle, resolve_password
from certswap.core import trust as trust_mod
from certswap.core.chain import chain_is_complete, complete_chain
from certswap.core.validation import key_matches_cert, verify_chain


def _trust_store_available() -> bool:
    try:
        trust_mod.discover()
    except trust_mod.TrustStoreNotFound:
        return False
    return True


def inspect_command(
    bundle_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=True, readable=True)
    ],
    password_env: Annotated[
        str | None, typer.Option("--password-env", help="Env var holding bundle password")
    ] = None,
    password_stdin: Annotated[
        bool, typer.Option("--password-stdin", help="Read bundle password from stdin")
    ] = False,
    fetch_intermediates: Annotated[
        bool,
        typer.Option(
            "--fetch-intermediates",
            help="Complete the chain via the AIA extension",
        ),
    ] = False,
    trust_store: Annotated[
        Path | None,
        typer.Option(
            "--trust-store",
            help="Override system trust store path",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON")
    ] = False,
    key: Annotated[
        Path | None,
        typer.Option(
            "--key",
            help="Private key path (for PKCS#7 or separate-file ingest)",
            exists=True,
            readable=True,
        ),
    ] = None,
    chain: Annotated[
        Path | None,
        typer.Option(
            "--chain",
            help="Chain path (separate-file ingest only)",
            exists=True,
            readable=True,
        ),
    ] = None,
) -> None:
    """Show the contents of a TLS bundle without performing any target work."""
    password = resolve_password(password_env, password_stdin)
    # Inspection is read-only, so a cert-only CA delivery is fine here;
    # plan/apply keep requiring the key.
    bundle = load_bundle(
        bundle_path, password=password, key=key, chain=chain, require_key=False
    )

    if fetch_intermediates:
        bundle = complete_chain(bundle, fetch=True)

    chain_complete = chain_is_complete(bundle.chain)
    key_ok: bool | None = None
    if bundle.private_key is not None:
        key_ok = key_matches_cert(bundle.private_key, bundle.leaf)

    chain_verified: bool | None = None
    if trust_store is not None or _trust_store_available():
        store_path = trust_store or trust_mod.discover()
        chain_verified = verify_chain(bundle, store_path)

    renderer = render_json if json_out else render_rich
    renderer(
        bundle,
        chain_complete=chain_complete,
        key_ok=key_ok,
        chain_verified=chain_verified,
    )

    if key_ok is False:
        raise typer.Exit(code=10)
