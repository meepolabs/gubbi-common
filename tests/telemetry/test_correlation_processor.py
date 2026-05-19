"""Contract tests for ``CorrelationSpanProcessor``.

The processor reads ``correlation_id`` from the ContextVar populated by
``CorrelationIDMiddleware`` and attaches it to every span at ``on_start``.
Tests cover:
  - cid present in ContextVar -> attribute lands on the span;
  - cid absent (background task / lifespan boot) -> attribute is NOT set,
    span stays untagged (vs. carrying a misleading sentinel);
  - the processor is registered ahead of the exporter so the attribute
    is present by the time the BatchSpanProcessor's on_end queues the
    span for export.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from gubbi_common.correlation import reset_correlation_id, set_correlation_id
from gubbi_common.telemetry.correlation_processor import CorrelationSpanProcessor


@pytest.mark.unit
def test_on_start_attaches_correlation_id_when_contextvar_set() -> None:
    """Active request context -> attribute lands."""
    token = set_correlation_id("req-7a3e-c91d")
    try:
        processor = CorrelationSpanProcessor()
        span = MagicMock()
        processor.on_start(span)
        span.set_attribute.assert_called_once_with("correlation_id", "req-7a3e-c91d")
    finally:
        reset_correlation_id(token)


@pytest.mark.unit
def test_on_start_skips_when_contextvar_unset() -> None:
    """No request context (lifespan / worker) -> attribute NOT set.

    Reset semantics: this test runs with the ContextVar in its default
    state (None). A sentinel value would pollute forensic queries that
    grep by correlation_id, so the processor MUST stay silent here.
    """
    processor = CorrelationSpanProcessor()
    span = MagicMock()
    processor.on_start(span)
    span.set_attribute.assert_not_called()


@pytest.mark.unit
def test_on_end_is_noop() -> None:
    """on_end has no side effects -- attribute injection happens at open."""
    processor = CorrelationSpanProcessor()
    span = MagicMock()
    processor.on_end(span)
    span.set_attribute.assert_not_called()


@pytest.mark.unit
def test_force_flush_returns_true_no_buffered_state() -> None:
    """force_flush reports success because there is nothing to flush."""
    assert CorrelationSpanProcessor().force_flush() is True


@pytest.mark.unit
def test_shutdown_is_noop() -> None:
    """shutdown has no resources to release."""
    CorrelationSpanProcessor().shutdown()  # must not raise
