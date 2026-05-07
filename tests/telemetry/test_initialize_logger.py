"""Unit tests for initialize_logger and its structlog processor chain.

Verifies:
* log directory creation
* JSON output to file handlers (via async structlog path)
* logger-name enrichment from _safe_add_logger_name
* correlation_id enrichment from _add_otel_context
"""

from __future__ import annotations

import json
import logging
from collections.abc import Generator
from pathlib import Path

import pytest

from gubbi_common.telemetry.logging import (
    _add_otel_context,
    initialize_logger,
    set_correlation_id,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _cleanup_logging() -> Generator[None, None, None]:
    """Reset logging global state after each test.

    Clears root log handlers so basicConfig(force=True) can install
    fresh ones for the next test, and resets structlog defaults to
    ensure configure() starts from a clean slate.
    """
    yield

    root = logging.getLogger()
    from logging.handlers import (  # noqa: PLC0415
        TimedRotatingFileHandler,
    )

    for handler in root.handlers[:]:
        if isinstance(handler, TimedRotatingFileHandler):
            root.removeHandler(handler)
            handler.close()
    root.setLevel(logging.WARNING)

    # Reset structlog so next initialize_logger gets a fresh chain.
    import structlog._config as cfg  # noqa: PLC0415

    cfg.reset_defaults()  # type: ignore[no-untyped-call]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_initialize_logger_creates_log_dir(tmp_path: Path) -> None:
    """initialize_logger creates the log directory if it is missing."""
    new_dir = tmp_path / "newdir"
    assert not new_dir.exists()

    initialize_logger("test_dir", log_dir=str(new_dir))

    assert new_dir.is_dir(), "log_dir should be created on initialization"


@pytest.mark.asyncio
async def test_initialize_logger_writes_json_to_file(tmp_path: Path) -> None:
    """After .info(), the log file contains a valid JSON line with event+attributes."""
    log_dir = tmp_path / "json_test"
    _ = initialize_logger("json_tester", log_dir=str(log_dir))

    import structlog  # noqa: PLC0415

    app_log = structlog.get_logger("json_tester")
    await app_log.info("hello", foo=1)  # type: ignore[arg-type]

    for handler in logging.getLogger().handlers:
        handler.flush()

    log_file = log_dir / "json_tester.log"
    assert log_file.exists(), f"log file {log_file} was not created"

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1, f"expected at least 1 log line, got: {lines!r}"

    parsed = json.loads(lines[0])

    assert parsed["event"] == "hello", f"event mismatch: {parsed['event']!r}"
    assert parsed.get("foo") == 1, f"foo mismatch in attributes: {parsed}"


@pytest.mark.asyncio
async def test_initialize_logger_logger_name_present_in_log(tmp_path: Path) -> None:
    """The rendered log line includes logger=<logger_name> from _safe_add_logger_name."""
    log_dir = tmp_path / "name_test"
    _ = initialize_logger("unique_logger_x", log_dir=str(log_dir))

    import structlog  # noqa: PLC0415

    app_log = structlog.get_logger("unique_logger_x")
    await app_log.info("test.name", attr="val")

    for handler in logging.getLogger().handlers:
        handler.flush()

    log_file = log_dir / "unique_logger_x.log"
    last_line = log_file.read_text(encoding="utf-8").strip().splitlines()[-1]
    parsed = json.loads(last_line)

    assert (
        parsed.get("logger") == "unique_logger_x"
    ), f"expected logger='unique_logger_x' in {parsed}"


def test_otel_context_processor_adds_correlation_id() -> None:
    """With set_correlation_id active, _add_otel_context attaches correlation_id."""
    import unittest.mock

    noop_span = unittest.mock.MagicMock()
    span_ctx = unittest.mock.MagicMock()
    span_ctx.is_valid = False
    noop_span.get_span_context.return_value = span_ctx

    with unittest.mock.patch(
        "gubbi_common.telemetry.logging.trace_get_current_span",
        return_value=noop_span,  # type: ignore[arg-type]
    ):
        token = set_correlation_id("abc")

        try:
            event_dict: dict[str, object] = {}
            result = _add_otel_context(None, "info", event_dict)

            assert "correlation_id" in result, f"correlation_id missing from {result}"
            assert result["correlation_id"] == "abc"

            # trace/span_id should NOT be present since span is invalid
            assert (
                "trace_id" not in result or result.get("trace_id") is None
            ), f"unexpected trace_id with invalid span: {result}"
        finally:
            from gubbi_common.telemetry.logging import (  # noqa: PLC0415
                _correlation_id_var,
            )

            _correlation_id_var.reset(token)


def test_telemetry_reexports_initialize_logger() -> None:
    """initialize_logger is accessible from gubbi_common.telemetry and in __all__."""
    from gubbi_common import telemetry  # noqa: PLC0415

    assert hasattr(telemetry, "initialize_logger")
    assert callable(telemetry.initialize_logger)

    assert "initialize_logger" in telemetry.__all__, "initialize_logger should be listed in __all__"


def test_public_symbols_in_all_for_init() -> None:
    """Telemetry __all__ contains the expected public symbols."""
    from gubbi_common.telemetry import __all__  # noqa: PLC0415

    required = {
        "BANNED_KEYS",
        "safe_set_attributes",
        "StructuredLogFormatter",
        "set_correlation_id",
        "reset_correlation_id",
        "get_correlation_id",
        "initialize_logger",
    }
    assert required.issubset(set(__all__)), f"missing from __all__: {required - set(__all__)}"


def test_initialize_logger_returns_bound_logger_type(tmp_path: Path) -> None:
    """initialize_logger returns a structlog-compatible logger object."""
    result = initialize_logger("type_test", log_dir=str(tmp_path / "life"))
    assert hasattr(result, "info"), f"unexpected return type: {type(result)}"
    info_method = result.info
    assert callable(info_method), f"unexpected info attribute type: {type(info_method)}"
