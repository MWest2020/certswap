"""`certswap plan <driver>` subcommands.

Each driver lives in its own ``_<driver>.py`` and registers itself with
``plan_app`` at import time.
"""

from __future__ import annotations

from certswap.commands.plan import _k8s, _local, _proxmox, _ssh  # noqa: F401 -- register
from certswap.commands.plan._app import plan_app

__all__ = ["plan_app"]
