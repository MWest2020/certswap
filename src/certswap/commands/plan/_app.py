"""Shared ``plan`` Typer subapp."""

from __future__ import annotations

import typer

plan_app = typer.Typer(
    name="plan",
    help="Show what apply would do, without changing anything.",
)
