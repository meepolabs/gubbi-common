"""Tests for the unified telemetry attribute allowlist."""

from __future__ import annotations

from typing import Any

import pytest

from gubbi_common.telemetry.allowlist import (
    BANNED_KEYS,
    SPAN_ALLOWLIST,
    safe_set_attributes,
)


class _SpanStub:
    """Captures set_attribute() calls for assertions."""

    def __init__(self) -> None:
        self.attrs: dict[str, Any] = {}

    def set_attribute(self, key: str, value: Any) -> None:
        self.attrs[key] = value


# ---------------------------------------------------------------------------
# BANNED_KEYS rejection
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("banned_key", sorted(BANNED_KEYS))
def test_banned_key_exact_match_dropped(banned_key: str) -> None:
    # Arrange
    span = _SpanStub()

    # Act
    safe_set_attributes("mcp.tool_call", span, {banned_key: "leak"})

    # Assert
    assert banned_key not in span.attrs


@pytest.mark.unit
def test_banned_substring_in_key_dropped() -> None:
    """Keys containing a banned token as substring are also dropped."""
    span = _SpanStub()
    safe_set_attributes(
        "mcp.tool_call",
        span,
        {
            "content_hash": "abc",  # contains "content"
            "email_hash": "def",  # contains "email"
            "client_user_agent_hash": "ghi",  # contains "user_agent"
            "tool.name": "ok",
        },
    )
    assert "content_hash" not in span.attrs
    assert "email_hash" not in span.attrs
    assert "client_user_agent_hash" not in span.attrs
    assert span.attrs["tool.name"] == "ok"


# ---------------------------------------------------------------------------
# Allowlist happy path
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_allowlisted_key_is_passed_through() -> None:
    span = _SpanStub()
    safe_set_attributes("mcp.tool_call", span, {"tool.name": "journal_append_entry"})
    assert span.attrs == {"tool.name": "journal_append_entry"}


@pytest.mark.unit
def test_non_allowlisted_key_is_dropped() -> None:
    span = _SpanStub()
    safe_set_attributes("mcp.tool_call", span, {"random_field": "x", "tool.name": "ok"})
    assert "random_field" not in span.attrs
    assert span.attrs["tool.name"] == "ok"


@pytest.mark.unit
def test_correlation_id_allowed_on_every_span() -> None:
    for span_name in SPAN_ALLOWLIST:
        span = _SpanStub()
        safe_set_attributes(span_name, span, {"correlation_id": "cid-123"})
        assert (
            span.attrs.get("correlation_id") == "cid-123"
        ), f"correlation_id was dropped on span {span_name!r}"


@pytest.mark.unit
def test_audit_write_allowlist_matches_documented_keys() -> None:
    """audit.write is the only span both repos defined; assert keys agree."""
    expected = {
        "event_type",
        "target_id",
        "actor_type",
        "success",
        "latency_ms",
        "correlation_id",
    }
    assert SPAN_ALLOWLIST["audit.write"] == frozenset(expected)


# ---------------------------------------------------------------------------
# Unknown span name
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_unknown_span_name_falls_back_to_banned_only() -> None:
    """Unknown span names: banned keys still dropped, all others dropped too."""
    span = _SpanStub()
    safe_set_attributes(
        "totally.unknown.span",
        span,
        {"content": "leak", "user_id": "u-1"},
    )
    # banned filtered
    assert "content" not in span.attrs
    # not in any allowlist either, so also dropped
    assert "user_id" not in span.attrs


@pytest.mark.unit
def test_unknown_span_name_logs_warning(caplog: pytest.LogCaptureFixture) -> None:
    import logging

    span = _SpanStub()
    with caplog.at_level(logging.WARNING, logger="gubbi_common.telemetry.allowlist"):
        safe_set_attributes("totally.unknown.span", span, {"foo": "bar"})
    assert any("unknown span_name" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Span allowlist coverage
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_every_span_allowlist_includes_correlation_id() -> None:
    """Every documented span has correlation_id available for transport middleware."""
    for span_name, allowed in SPAN_ALLOWLIST.items():
        assert "correlation_id" in allowed, f"span {span_name!r} is missing correlation_id"


@pytest.mark.unit
def test_journalctl_spans_present() -> None:
    """Sanity: journalctl span names survived the merge."""
    for name in (
        "mcp.tool_call",
        "mcp.tool_response_size_check",
        "db.query.user_scoped",
        "embedding.encode",
        "cipher.encrypt",
        "cipher.decrypt",
        "audit.write",
    ):
        assert name in SPAN_ALLOWLIST


@pytest.mark.unit
def test_cloud_spans_present() -> None:
    """Sanity: cloud-api span names survived the merge."""
    for name in (
        "auth.bearer_introspect",
        "auth.session_resolve",
        "auth.subscription_check",
        "auth.ratelimit_check",
        "auth.jit_provision",
        "gateway.forward",
        "webhook.kratos_identity_created",
        "webhook.kratos_identity_updated",
        "webhook.kratos_identity_deleted",
    ):
        assert name in SPAN_ALLOWLIST
