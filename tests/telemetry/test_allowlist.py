"""Tests for the unified telemetry attribute allowlist."""

from __future__ import annotations

from typing import Any

import pytest

from gubbi_common.telemetry.allowlist import (
    BANNED_KEYS,
    DERIVATIVE_MODIFIERS,
    NEVER_EXEMPT_BASES,
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
    allowlist = {"my.span": frozenset({"good_field"})}
    span = _SpanStub()
    safe_set_attributes(
        "my.span", span, {"good_field": "v", "other_field": "x"}, allowlist=allowlist
    )
    assert span.attrs == {"good_field": "v"}


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
# Standard substring deny (no derivative suffix)
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
    """Keys containing a banned token as substring (no derivative suffix) are dropped."""
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
# Derivative-suffix exemption: <banned>_<derivative> -> ALLOWED
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize(
    "key",
    [
        "email_hash",
        "body_size",
        "query_count",
        "summary_fp",
        "messages_len",
        "reasoning_hash",
        "ip_address_hash",
        "user_agent_hash",
        "content_bytes",
        "client_user_agent_hash",  # currently shipping in cloud-api -- must not regress
    ],
)
def test_derivative_suffix_allows_banned_base(key: str) -> None:
    """`<banned>_<derivative>` keys pass when allowlisted -- they describe a privacy-safe quantity."""
    allowlist = {"test.span": frozenset({key})}
    span = _SpanStub()
    safe_set_attributes("test.span", span, {key: "abc"}, allowlist=allowlist)
    assert span.attrs == {key: "abc"}


@pytest.mark.unit
def test_suffixed_key_not_in_allowlist_still_dropped() -> None:
    """Even with a derivative suffix, a key not in the per-span allowlist is dropped."""
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
# Non-derivative suffixes: `_id`, `_present` -> still BANNED if base is banned
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize(
    "key",
    [
        "email_id",
        "email_present",
        "content_id",
        "body_present",
        "messages_id",
        "user_agent_id",
        "ip_address_present",
    ],
)
def test_non_derivative_suffix_does_not_exempt(key: str) -> None:
    """`_id` and `_present` are NOT structural exemptions -- BANNED_KEYS substring still applies."""
    allowlist = {"test.span": frozenset({key})}
    span = _SpanStub()
    safe_set_attributes("test.span", span, {key: "leak"}, allowlist=allowlist)
    assert key not in span.attrs


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
def test_derivative_modifiers_defined() -> None:
    expected = frozenset({"_hash", "_count", "_size", "_len", "_fp", "_bytes"})
    assert expected == DERIVATIVE_MODIFIERS


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
