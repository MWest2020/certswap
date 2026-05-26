"""Apply-time helpers for the k8s driver: timed step recorder."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from certswap.drivers.base import ApplyResult, StepResult


def record_step(
    result: ApplyResult, description: str, action: Callable[[], Any]
) -> None:
    """Run ``action`` and append a :class:`StepResult` to ``result``.

    Exceptions are caught and recorded as a failed step rather than
    propagating; the caller decides whether to abort on the first
    non-ok step.
    """
    start = time.perf_counter()
    try:
        action()
        ok = True
        err: str | None = None
    except Exception as exc:
        ok = False
        err = str(exc)
    result.steps.append(
        StepResult(
            description=description,
            before=None,
            after=None,
            duration_ms=int((time.perf_counter() - start) * 1000),
            ok=ok,
            error=err,
        )
    )
