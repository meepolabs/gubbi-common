"""Tests for the unified telemetry attribute allowlist."""

from __future__ import annotations

from typing import Any

import pytest

from gubbi_common.telemetry.allowlist import (
    BANNED_KEYS,
    NEVER_EXEMPT_BASES,
    TRAILING_MODIFIERS,
    safe_set_attributes,
)


class _SpanStub:
    """Captures the single set_attributes() call for assertions."""

    def __init__(self) -> None:
        self.attrs: dict[str, Any] = {}

    def set_attributes(self, attrs: dict[str, Any]) -> None:
        self.attrs.update(attrs)


# ===========================================================================
# Injection: the allowlist kwarg
# ===========================================================================


@pytest.mark.unit
def test_allowlist_kwarg_required() -> None:
    """Calling safe_set_attributes without allowlist raises TypeError."""
    with pytest.raises(TypeError):
        safe_set_attributes("test", _SpanStub(), {})  # type: ignore[call-arg]


@pytest.mark.unit
def test_allowlist_drives_accepted_keys() -> None:
    """Only keys in the per-span allowlist pass through."""
    allowlist = {"my.span": frozenset({"good_key"})}
    span = _SpanStub()
    safe_set_attributes("my.span", span, {"good_key": "v", "bad_key": "x"}, allowlist=allowlist)
    assert span.attrs == {"good_key": "v"}


@pytest.mark.unit
def test_allowlisted_key_passes_when_not_banned() -> None:
    """A key that is both allowlisted and not banned passes through."""
    allowlist = {"s": frozenset({"safe_field"})}
    span = _SpanStub()
    safe_set_attributes("s", span, {"safe_field": "ok"}, allowlist=allowlist)
    assert span.attrs == {"safe_field": "ok"}


# ===========================================================================
# Strict-by-default: unknown span names drop ALL attributes
# ===========================================================================


@pytest.mark.unit
def test_unknown_span_drops_all_attrs() -> None:
    """Unknown span names drop ALL attributes regardless of allowlist content."""
    allowlist = {"known.span": frozenset({"foo"})}
    span = _SpanStub()
    safe_set_attributes("unknown.span", span, {"foo": "bar"}, allowlist=allowlist)
    assert span.attrs == {}


@pytest.mark.unit
def test_unknown_span_logs_debug(caplog: pytest.LogCaptureFixture) -> None:
    """Unknown span emits exactly one structured DEBUG log entry."""
    import logging

    allowlist: dict[str, frozenset[str]] = {"known.span": frozenset()}
    span = _SpanStub()
    with caplog.at_level(logging.DEBUG, logger="gubbi_common.telemetry.allowlist"):
        safe_set_attributes("unknown.span", span, {"x": "y"}, allowlist=allowlist)
    matching = [r for r in caplog.records if "unknown span_name" in r.message]
    assert len(matching) == 1
    # The span name must appear in the message, but not the attrs themselves
    assert "unknown.span" in matching[0].message


# ===========================================================================
# Standard substring deny (no trailing modifier)
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize("banned_key", sorted(BANNED_KEYS))
def test_banned_key_exact_match_dropped(banned_key: str) -> None:
    """Every BANNED_KEYS entry dropped by exact match even if allowlisted."""
    allowlist = {"test.span": frozenset({banned_key})}
    span = _SpanStub()
    safe_set_attributes("test.span", span, {banned_key: "leak"}, allowlist=allowlist)
    assert banned_key not in span.attrs


@pytest.mark.unit
def test_banned_substring_in_key_dropped() -> None:
    """Keys containing a banned token as substring (no trailing modifier) are dropped."""
    allowlist = {"test.span": frozenset({"email_leak", "badcontent", "good"})}
    span = _SpanStub()
    safe_set_attributes(
        "test.span",
        span,
        {"email_leak": "a", "badcontent": "b", "good": "ok"},
        allowlist=allowlist,
    )
    assert "email_leak" not in span.attrs  # contains "email" -> banned
    assert "badcontent" not in span.attrs  # contains "content" -> banned
    assert span.attrs["good"] == "ok"  # no banned substring -> passes


@pytest.mark.unit
def test_non_banned_allowlisted_key_passes() -> None:
    """A key that is not banned and is allowlisted passes through."""
    allowlist = {"s": frozenset({"tool.name"})}
    span = _SpanStub()
    safe_set_attributes("s", span, {"tool.name": "foo"}, allowlist=allowlist)
    assert span.attrs["tool.name"] == "foo"


# ===========================================================================
# Trailing-modifier exemption
# ===========================================================================


@pytest.mark.unit
def test_trailing_modifier_exemption_allows_suffixed_keys() -> None:
    """Keys ending in a TRAILING_MODIFIERS suffix pass when allowlisted."""
    allowlist = {
        "test.span": frozenset(
            {
                "client_user_agent_hash",
                "query_count",
                "email_present",
                "body_size",
            }
        ),
    }
    span = _SpanStub()
    safe_set_attributes(
        "test.span",
        span,
        {
            "client_user_agent_hash": "abc",
            "query_count": "42",
            "email_present": "true",
            "body_size": "1024",
        },
        allowlist=allowlist,
    )
    assert span.attrs == {
        "client_user_agent_hash": "abc",
        "query_count": "42",
        "email_present": "true",
        "body_size": "1024",
    }


@pytest.mark.unit
def test_suffixed_key_not_in_allowlist_still_dropped() -> None:
    """Even with a trailing modifier, a key not in the per-span allowlist is dropped."""
    allowlist = {"test.span": frozenset({"other"})}
    span = _SpanStub()
    safe_set_attributes(
        "test.span",
        span,
        {"client_user_agent_hash": "abc"},
        allowlist=allowlist,
    )
    assert span.attrs == {}


@pytest.mark.unit
def test_bare_banned_still_dropped_even_if_allowlisted() -> None:
    """Non-suffixed banned keys are still dropped even if in the per-span allowlist."""
    allowlist = {"test.span": frozenset({"email", "user_agent", "content", "query"})}
    span = _SpanStub()
    safe_set_attributes(
        "test.span",
        span,
        {"email": "a", "user_agent": "b", "content": "c", "query": "d"},
        allowlist=allowlist,
    )
    assert span.attrs == {}


# ===========================================================================
# NEVER_EXEMPT bases
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize(
    "banned_attr",
    [
        "password_hash",
        "bcrypt_password_hash",
        "session_token_id",
        "api_credential_fp",
        "secret_hash",
    ],
)
def test_never_exempt_bases_dropped(banned_attr: str) -> None:
    """Attributes whose base contains a NEVER_EXEMPT_BASES term are dropped even if allowlisted."""
    allowlist = {"test.span": frozenset({banned_attr})}
    span = _SpanStub()
    safe_set_attributes("test.span", span, {banned_attr: "leak"}, allowlist=allowlist)
    assert banned_attr not in span.attrs


@pytest.mark.unit
def test_suffixed_password_still_dropped_via_never_exempt() -> None:
    """password_hash is dropped because base 'password' is in NEVER_EXEMPT_BASES."""
    allowlist = {"s": frozenset({"password_hash"})}
    span = _SpanStub()
    safe_set_attributes("s", span, {"password_hash": "x"}, allowlist=allowlist)
    assert "password_hash" not in span.attrs


# ===========================================================================
# Sanity: constants are defined with expected values
# ===========================================================================


@pytest.mark.unit
def test_trailing_modifiers_defined() -> None:
    assert TRAILING_MODIFIERS == (
        "_hash",
        "_count",
        "_size",
        "_bytes",
        "_length",
        "_present",
        "_fp",
        "_id",
    )


@pytest.mark.unit
def test_never_exempt_bases_defined() -> None:
    assert NEVER_EXEMPT_BASES == (
        "password",
        "secret",
        "token",
        "credential",
        "key",
    )


# ===========================================================================
# No SPAN_ALLOWLIST export
# ===========================================================================


@pytest.mark.unit
def test_span_allowlist_not_exported() -> None:
    """SPAN_ALLOWLIST is no longer a module attribute or in __all__."""
    import gubbi_common.telemetry.allowlist as m

    assert not hasattr(m, "SPAN_ALLOWLIST")
    # Also verify the telemetry package __all__ does not list it
    from gubbi_common.telemetry import __all__ as telemetry_all

    assert "SPAN_ALLOWLIST" not in telemetry_all
