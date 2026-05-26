"""Driver protocol and shared models.

A driver is a thin object exposing ``plan``, ``apply``, and ``verify``.
Each is one file in this package. The CLI looks drivers up by name via
:func:`get_driver`.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from certswap.models import CertBundle


class TargetContext(BaseModel):
    """Carries the user-supplied driver-specific configuration."""

    model_config = ConfigDict(extra="forbid")

    driver: str
    identifier: str
    options: dict[str, Any] = Field(default_factory=dict)


class PlanStep(BaseModel):
    description: str
    before: str | None = None
    would_do: str = ""


class Plan(BaseModel):
    driver: str
    identifier: str
    steps: list[PlanStep] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return bool(self.blockers)


class StepResult(BaseModel):
    description: str
    before: str | None = None
    after: str | None = None
    duration_ms: int = 0
    ok: bool = True
    error: str | None = None


class CheckResult(BaseModel):
    name: str
    ok: bool
    detail: str | None = None


class VerifyResult(BaseModel):
    ok: bool
    checks: list[CheckResult] = Field(default_factory=list)


class ApplyResult(BaseModel):
    driver: str
    identifier: str
    steps: list[StepResult] = Field(default_factory=list)
    exit_code: int = 0
    verify: VerifyResult | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@runtime_checkable
class EgressDriver(Protocol):
    name: str

    def plan(self, bundle: CertBundle, ctx: TargetContext) -> Plan: ...

    def apply(self, bundle: CertBundle, ctx: TargetContext) -> ApplyResult: ...

    def verify(self, ctx: TargetContext) -> VerifyResult: ...


class UnknownDriverError(LookupError):
    """Raised when a driver name has not been registered."""


_REGISTRY: dict[str, EgressDriver] = {}


def register(driver: EgressDriver) -> None:
    _REGISTRY[driver.name] = driver


def get_driver(name: str) -> EgressDriver:
    if name not in _REGISTRY:
        raise UnknownDriverError(
            f"no driver registered under {name!r}; "
            f"available: {sorted(_REGISTRY) or '(none)'}"
        )
    return _REGISTRY[name]


def registered_names() -> list[str]:
    return sorted(_REGISTRY)
