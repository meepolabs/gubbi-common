"""Unit tests for the canonical StructuredLogFormatter.

Covers both gubbi-shape (default) and cloud-shape (explicit kwargs) output.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from gubbi_common.telemetry.logging import (
    StructuredLogFormatter,
    _get_otel_ids,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


class _SpanContextStub:
    """Fake SpanContext with valid trace/span IDs."""

    is_valid = True
    trace_id = 0x1234567890ABCDEF1234567890ABCDEF
    span_id = 0x1234567890ABCDEF


class _SpanStub:
    """Fake OTel Span returning a fixed context."""

    def __init__(self) -> None:
        self.ctx = _SpanContextStub()

    def get_span_context(self) -> _SpanContextStub:
        return self.ctx


def _reset_correlation() -> None:
    """Reset the correlation_id ContextVar to its default (None)."""
    from gubbi_common.telemetry import logging as log_mod

    log_mod._correlation_id_var.set(None)  # type: ignore[union-attr]


def _make_record(
    msg: Any = "test.event",
    level: int = logging.INFO,
    args: Any = None,
    **extra: object,
) -> logging.LogRecord:
    """Create a minimal LogRecord with optional __dict__ extras."""
    record = logging.LogRecord(
        name="test",
        level=level,
        pathname="tests/telemetry/test_logging.py",
        lineno=1,
        msg=msg,
        args=args if args is not None else (() if isinstance(msg, str) else {}),
        exc_info=None,
    )
    # Inject extra fields into __dict__ (simulates ``extra=`` on logging call)
    for k, v in extra.items():
        setattr(record, k, v)
    return record


def parse_line(line: str) -> dict[str, Any]:
    """Deserialize one JSON log line."""
    return json.loads(line)


# ---------------------------------------------------------------------------
# a) Default-mode (gubbi-shape) test
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_default_mode_gubbi_shape() -> None:
    """Default formatter emits correct gubbi-shape with attributes when extras exist."""
    # Pass service_name explicitly so the assertion below is deterministic
    # regardless of OTEL_SERVICE_NAME in the test runner's environment.
    formatter = StructuredLogFormatter(service_name="gubbi")
    record = _make_record("tool.call", extra_field="hello")

    output = formatter.format(record)
    parsed = parse_line(output)

    required_keys = {
        "timestamp",
        "level",
        "service",
        "correlation_id",
        "trace_id",
        "span_id",
        "event",
    }
    assert required_keys.issubset(
        parsed.keys()
    ), f"missing keys: {required_keys - set(parsed.keys())}"

    # attributes present and contains the extra field
    assert "attributes" in parsed
    assert parsed["attributes"]["extra_field"] == "hello"

    # service is asserted explicitly; pass service_name="gubbi" so the test
    # is deterministic regardless of OTEL_SERVICE_NAME in the runner env.
    assert parsed["service"] == "gubbi"
    assert parsed["level"] == "INFO"
    assert parsed["event"] == "tool.call"


@pytest.mark.unit
def test_default_mode_no_extras() -> None:
    """Default formatter with no extras still emits all top-level keys."""
    formatter = StructuredLogFormatter()
    record = _make_record("no.extras")

    output = formatter.format(record)
    parsed = parse_line(output)

    required_keys = {
        "timestamp",
        "level",
        "service",
        "correlation_id",
        "trace_id",
        "span_id",
        "event",
    }
    assert required_keys.issubset(parsed.keys())


# ---------------------------------------------------------------------------
# b) Cloud-mode test
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_cloud_mode_emits_attributes_dict() -> None:
    """Cloud-mode formatter reads attributes from record.attributes_dict."""
    formatter = StructuredLogFormatter(
        service_name="cloud-api",
        attributes_attr_name="attributes_dict",
        dict_msg_attribute_key="event_dict",
        omit_empty_attributes=False,
    )
    record = _make_record("cloud.event")
    record.correlation_id = "cid-42"
    record.trace_id = "00" * 16
    record.span_id = "00" * 8
    record.attributes_dict = {"http.method": "GET", "url.path": "/health"}

    output = formatter.format(record)
    parsed = parse_line(output)

    assert parsed["service"] == "cloud-api"
    assert parsed["correlation_id"] == "cid-42"
    assert parsed["trace_id"] == "00" * 16
    assert parsed["span_id"] == "00" * 8
    assert "attributes" in parsed
    assert parsed["attributes"]["http.method"] == "GET"


@pytest.mark.unit
def test_cloud_mode_omit_false_always_emits_attributes() -> None:
    """omit_empty_attributes=False means 'attributes' is always present, even empty."""
    formatter = StructuredLogFormatter(
        service_name="cloud-api",
        attributes_attr_name="attributes_dict",
        omit_empty_attributes=False,
    )
    record = _make_record("empty")

    output = formatter.format(record)
    parsed = parse_line(output)

    assert "attributes" in parsed
    assert parsed["attributes"] == {}


# ---------------------------------------------------------------------------
# c) Correlation fallback chain tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_correlation_from_contextvar() -> None:
    """When no record.correlation_id, falls back to contextvar."""
    from gubbi_common.telemetry import logging as log_mod

    formatter = StructuredLogFormatter()
    log_mod.set_correlation_id("ctx-cid-123")
    try:
        record = _make_record("ctx.cid")
        output = formatter.format(record)
        parsed = parse_line(output)
        assert parsed["correlation_id"] == "ctx-cid-123"
    finally:
        _reset_correlation()


@pytest.mark.unit
def test_correlation_from_record_attr_overrides_contextvar() -> None:
    """record.correlation_id takes priority over contextvar."""
    from gubbi_common.telemetry import logging as log_mod

    formatter = StructuredLogFormatter()
    log_mod.set_correlation_id("ctx-fallback")
    try:
        record = _make_record("record.cid")
        record.correlation_id = "rec-456"
        output = formatter.format(record)
        parsed = parse_line(output)
        assert (
            parsed["correlation_id"] == "rec-456"
        ), "record attribute must override contextvar fallback"
    finally:
        _reset_correlation()


@pytest.mark.unit
def test_correlation_none_when_nothing_set() -> None:
    """When neither record nor context has a correlation_id, value is null."""

    formatter = StructuredLogFormatter()
    _reset_correlation()  # ensure clean state
    record = _make_record("no.cid")
    output = formatter.format(record)
    parsed = parse_line(output)
    assert parsed["correlation_id"] is None


# ---------------------------------------------------------------------------
# d) Empty attributes tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_omit_empty_attributes_true_no_attr_key_when_empty() -> None:
    """With omit_empty_attributes=True, 'attributes' key absent when no extras."""
    formatter = StructuredLogFormatter(omit_empty_attributes=True)
    record = _make_record("no.extras.here")

    output = formatter.format(record)
    parsed = parse_line(output)

    assert "attributes" not in parsed


@pytest.mark.unit
def test_omit_empty_attributes_false_emits_empty_dict() -> None:
    """With omit_empty_attributes=False, 'attributes' is always {} when no extras."""
    formatter = StructuredLogFormatter(omit_empty_attributes=False)
    record = _make_record("no.extras.here")

    output = formatter.format(record)
    parsed = parse_line(output)

    assert "attributes" in parsed
    assert parsed["attributes"] == {}


# ---------------------------------------------------------------------------
# e) Dict-msg interop test
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_dict_msg_attribute_key_copies_dict() -> None:
    """When dict_msg_attribute_key is set and msg is a dict, dict goes into attributes."""
    formatter = StructuredLogFormatter(
        dict_msg_attribute_key="event_dict",
        omit_empty_attributes=True,
    )
    msg_dict = {"level": "INFO", "message": "hello"}
    record = _make_record(msg_dict)
    record.args = {}

    output = formatter.format(record)
    parsed = parse_line(output)

    assert "attributes" in parsed
    assert parsed["attributes"]["event_dict"] == msg_dict


@pytest.mark.unit
def test_dict_msg_attribute_key_not_set_when_msg_is_string() -> None:
    """dict_msg_attribute_key is ignored when record.msg is not a dict."""
    formatter = StructuredLogFormatter(
        dict_msg_attribute_key="event_dict",
    )
    record = _make_record("plain.string.event")

    output = formatter.format(record)
    parsed = parse_line(output)

    assert "event_dict" not in parsed.get("attributes", {})


# ---------------------------------------------------------------------------
# f) Event derivation: %-formatting branch
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_derive_event_percent_formatting() -> None:
    """_derive_event handles %-formatting when record.args is non-empty."""
    formatter = StructuredLogFormatter()
    record = _make_record("hello %s", args=("world",))
    output = formatter.format(record)
    parsed = parse_line(output)
    assert parsed["event"] == "hello world"


# ---------------------------------------------------------------------------
# g) OTel IDs from _get_otel_ids (unit access)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_get_otel_ids_fallback_without_opentelemetry() -> None:
    """Without opentelemetry installed, _get_otel_ids returns (None, None)."""
    tid, sid = _get_otel_ids()
    assert tid is None
    assert sid is None


@pytest.mark.unit
def test_get_otel_ids_invalid_span_fallback() -> None:
    """When OTel is available but span is invalid, returns (None, None).

    Uses unittest.mock.patch.dict to inject a fake opentelemetry module
    into sys.modules so that the import inside _get_otel_ids succeeds but
    the span remains invalid.
    """
    from unittest.mock import MagicMock, patch

    fake_span_ctx = MagicMock()
    fake_span_ctx.is_valid = False
    fake_span_ctx.trace_id = 0
    fake_span_ctx.span_id = 0

    fake_span = MagicMock()
    fake_span.get_span_context.return_value = fake_span_ctx

    fake_trace = MagicMock()
    fake_trace.get_current_span.return_value = fake_span

    fake_otel = MagicMock()
    fake_otel.trace = fake_trace

    with patch.dict(
        "sys.modules",
        {"opentelemetry": fake_otel, "opentelemetry.trace": fake_trace},
        clear=False,
    ):
        # _get_otel_ids imports inside its try block on every call;
        # with the fakes in sys.modules the import succeeds.
        tid, sid = _get_otel_ids()
        assert tid is None
        assert sid is None


# ---------------------------------------------------------------------------
# h) Re-export verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_telemetry_package_reexports() -> None:
    """Public StructuredLogFormatter and helpers accessible from gubbi_common.telemetry."""
    from gubbi_common.telemetry import (
        StructuredLogFormatter,
        get_correlation_id,
        set_correlation_id,
    )

    assert callable(set_correlation_id)
    assert callable(get_correlation_id)
    assert isinstance(StructuredLogFormatter(), logging.Formatter)


@pytest.mark.unit
def test_private_helper_not_reexported() -> None:
    """_get_otel_ids is private; not re-exported from gubbi_common.telemetry package."""
    import gubbi_common.telemetry as t

    assert not hasattr(t, "_get_otel_ids"), (
        "_get_otel_ids should remain accessible only via "
        "gubbi_common.telemetry.logging._get_otel_ids"
    )


@pytest.mark.unit
def test_public_symbols_in_all() -> None:
    """__all__ contains all public symbols (and excludes private helpers)."""
    from gubbi_common.telemetry import __all__

    required = {
        "BANNED_KEYS",
        "safe_set_attributes",
        "StructuredLogFormatter",
        "set_correlation_id",
        "get_correlation_id",
    }
    assert required.issubset(set(__all__)), f"missing from __all__: {required - set(__all__)}"
    assert "_get_otel_ids" not in __all__, "_get_otel_ids must not appear in __all__"


# ---------------------------------------------------------------------------
# i) ensure_ascii flag
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_json_output_is_valid_utf8_by_default() -> None:
    """ensure_ascii=False (default) allows UTF-8 in output."""
    formatter = StructuredLogFormatter()
    record = _make_record("cafe\u0301")

    output = formatter.format(record)
    parsed = parse_line(output)
    # The event should contain the raw unicode character
    assert "cafe" in parsed["event"]


@pytest.mark.unit
def test_ensure_ascii_true_escapes_non_ascii() -> None:
    """ensure_ascii=True emits \\u-escapes for non-ASCII in raw JSON output."""
    formatter = StructuredLogFormatter(ensure_ascii=True)
    record = _make_record("caf\u00e9")
    output = formatter.format(record)

    # Check raw JSON string: ensure_ascii should produce \\u-escapes
    assert "\\u00e9" in output, f"expected ascii escape, got: {output!r}"

    # After parsing back, the event is decoded (normal JSON behavior)
    parsed = json.loads(output)
    assert parsed["event"] == "caf\u00e9"


@pytest.mark.unit
def test_ensure_ascii_false_preserves_unicode() -> None:
    """ensure_ascii=False writes raw Unicode in the JSON output."""
    formatter = StructuredLogFormatter(ensure_ascii=False)
    record = _make_record("caf\u00e9")
    output = formatter.format(record)

    # check the event is correct after parsing
    parsed = json.loads(output)
    assert parsed["event"] == "caf\u00e9"

    # raw JSON should contain the actual Unicode char, not \\u escapes
    assert "\\u00e9" not in output


# ---------------------------------------------------------------------------
# j) Version bump verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_version_is_050() -> None:
    """v0.5.0 — minor bump for the new StructuredLogFormatter public API."""
    import gubbi_common

    assert gubbi_common.__version__ == "0.5.0"
