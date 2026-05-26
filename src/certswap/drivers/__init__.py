"""Egress drivers.

Importing this package registers every built-in driver as a side effect.
"""

from __future__ import annotations

from certswap.drivers import local  # noqa: F401 -- import-for-side-effects
from certswap.drivers.base import (
    ApplyResult,
    CheckResult,
    EgressDriver,
    Plan,
    PlanStep,
    StepResult,
    TargetContext,
    UnknownDriverError,
    VerifyResult,
    get_driver,
    register,
    registered_names,
)

__all__ = [
    "ApplyResult",
    "CheckResult",
    "EgressDriver",
    "Plan",
    "PlanStep",
    "StepResult",
    "TargetContext",
    "UnknownDriverError",
    "VerifyResult",
    "get_driver",
    "register",
    "registered_names",
]
