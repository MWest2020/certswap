"""`certswap apply <driver>` subcommands."""

from __future__ import annotations

from certswap.commands.apply import _k8s, _local, _proxmox, _ssh  # noqa: F401 -- register
from certswap.commands.apply._app import apply_app

__all__ = ["apply_app"]
