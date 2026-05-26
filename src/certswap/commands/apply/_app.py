"""Shared ``apply`` Typer subapp."""

from __future__ import annotations

import typer

apply_app = typer.Typer(name="apply", help="Execute a deployment and write evidence.")
