"""Tests for ``gubbi_common.telemetry.otel.safe_instrument``.

Extracted as part of A7 Q1: both gubbi and gubbi-cloud need an
auto-instrumentor wrapper that swallows per-library failures so a
broken Instrumentor cannot crash startup. Tests assert:

* Success path -- factory runs, DEBUG line emitted.
* Failure path -- exception swallowed, WARNING line names the
  instrumentor + the exception.
"""

from __future__ import annotations

import logging

import pytest

from gubbi_common.telemetry.otel import safe_instrument


@pytest.mark.unit
def test_safe_instrument_runs_factory_and_logs_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Arrange
    calls: list[int] = []

    def factory() -> None:
        calls.append(1)

    # Act
    with caplog.at_level(logging.DEBUG, logger="gubbi_common.telemetry.otel"):
        safe_instrument("FastAPI", factory)

    # Assert
    assert calls == [1], "factory should have been invoked exactly once"
    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    # Require BOTH the display name AND the word "instrumentor" so a format
    # regression that drops either (e.g. concatenating "%sInstrumentor"
    # without a space, or dropping the name) is caught here, not in
    # production grep dashboards.
    assert any(
        "FastAPI" in r.getMessage() and "instrument" in r.getMessage().lower()
        for r in debug_records
    ), (
        f"expected DEBUG log naming 'FastAPI' AND mentioning instrumentation; "
        f"got {[r.getMessage() for r in caplog.records]}"
    )


@pytest.mark.unit
def test_safe_instrument_swallows_failure_and_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Arrange
    def factory() -> None:
        raise RuntimeError("instrumentor went bang")

    # Act
    with caplog.at_level(logging.WARNING, logger="gubbi_common.telemetry.otel"):
        safe_instrument("HTTPX", factory)  # MUST NOT raise

    # Assert
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_records, "expected a WARNING log on instrumentor failure"
    msg = warning_records[0].getMessage()
    # Require BOTH the display name AND the word "instrumentor" -- the
    # previous OR-form let "%sInstrumentor failed" (no separator) pass
    # even though operators grepping "instrumentor" miss it. The AND-form
    # forces a real space-separated rendering.
    assert "HTTPX" in msg, f"warning must name 'HTTPX'; got {msg!r}"
    assert (
        "instrumentor" in msg.lower()
    ), f"warning must include the word 'instrumentor' (lowercased); got {msg!r}"
    assert (
        "instrumentor went bang" in msg
    ), f"warning must include the original exception text; got {msg!r}"


@pytest.mark.unit
def test_safe_instrument_swallows_arbitrary_exception() -> None:
    """Broad Exception swallow -- both ImportError and ValueError must be caught."""

    def import_error_factory() -> None:
        raise ImportError("missing dep")

    def value_error_factory() -> None:
        raise ValueError("bad config")

    # Both must not raise.
    safe_instrument("Redis", import_error_factory)
    safe_instrument("Anthropic", value_error_factory)
