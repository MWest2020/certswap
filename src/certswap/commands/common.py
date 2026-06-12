"""Shared helpers for plan / apply / verify implementations.

Render helpers live in :mod:`certswap.commands._render`; option builders
live in :mod:`certswap.commands._options`. Both are re-exported here for
backward compatibility so existing call sites keep working.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import typer

from certswap.commands._options import (
    build_k8s_options,
    build_local_options,
    build_ssh_options,
)
from certswap.commands._render import (
    console,
    render_apply,
    render_plan,
    render_verify,
)
from certswap.ingest import IngestError, ingest
from certswap.models import CertBundle


def resolve_password(password_env: str | None, password_stdin: bool) -> bytes | None:
    if password_env and password_stdin:
        raise typer.BadParameter(
            "use either --password-env or --password-stdin, not both"
        )
    if password_env:
        value = os.environ.get(password_env)
        if value is None:
            raise typer.BadParameter(f"env var {password_env!r} is not set")
        return value.encode("utf-8")
    if password_stdin:
        return sys.stdin.read().rstrip("\n").encode("utf-8")
    return None


def load_bundle(
    bundle_path: Path,
    *,
    password: bytes | None,
    key: Path | None,
    chain: Path | None,
    require_key: bool = True,
) -> CertBundle:
    try:
        return ingest(
            bundle_path,
            password=password,
            key_path=key,
            chain_path=chain,
            require_key=require_key,
        )
    except (IngestError, ValueError) as exc:
        typer.echo(f"ingest failed: {exc}", err=True)
        raise typer.Exit(code=30) from exc


def confirm_or_exit(message: str, *, yes: bool, json_out: bool) -> None:
    """Prompt for confirmation unless --yes is given.

    ``--json`` implies non-interactive (acts like ``--yes``). We never mix
    JSON output with an interactive prompt.
    """
    if yes or json_out:
        return
    if not typer.confirm(message, default=False):
        typer.echo("aborted", err=True)
        raise typer.Exit(code=0)


__all__ = [
    "build_k8s_options",
    "build_local_options",
    "build_ssh_options",
    "confirm_or_exit",
    "console",
    "load_bundle",
    "render_apply",
    "render_plan",
    "render_verify",
    "resolve_password",
]
