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
def test_v043_pii_tokens_present_in_banned_keys() -> None:
    """v0.4.3 added modern PII tokens; future removal would silently regress.

    Each of these covers a distinct PII surface: phone numbers, postal/email
    addresses, LLM prompt/completion text fields. Removal would re-open the
    PII leak vector.
    """
    for token in ("phone", "address", "prompt", "completion", "response_text"):
        assert token in BANNED_KEYS, f"BANNED_KEYS missing v0.4.3 token: {token!r}"


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


# ===========================================================================
# Public is_banned_key promotion (formerly _is_banned)
# ===========================================================================


@pytest.mark.unit
def test_is_banned_key_public_export() -> None:
    """is_banned_key is importable from the telemetry package root."""
    from gubbi_common.telemetry import is_banned_key

    assert callable(is_banned_key)


@pytest.mark.unit
def test_is_banned_key_credential_substring() -> None:
    """A bare BANNED_KEYS substring (no derivative suffix) is banned."""
    from gubbi_common.telemetry import is_banned_key

    assert is_banned_key("password")
    assert is_banned_key("user_email")
    assert is_banned_key("client_user_agent")


@pytest.mark.unit
def test_is_banned_key_derivative_suffix_exempt() -> None:
    """A derivative suffix on a banned base is NOT banned."""
    from gubbi_common.telemetry import is_banned_key

    assert not is_banned_key("email_hash")
    assert not is_banned_key("body_size")
    assert not is_banned_key("query_count")


@pytest.mark.unit
def test_is_banned_key_never_exempt_base_overrides_suffix() -> None:
    """A NEVER_EXEMPT_BASES base remains banned even with a derivative suffix."""
    from gubbi_common.telemetry import is_banned_key

    assert is_banned_key("password_hash")
    assert is_banned_key("session_token_id")
    assert is_banned_key("api_credential_fp")


@pytest.mark.unit
def test_is_banned_alias_still_works() -> None:
    """The legacy ``_is_banned`` alias remains importable for one minor."""
    from gubbi_common.telemetry.allowlist import _is_banned, is_banned_key

    assert _is_banned is is_banned_key


# ===========================================================================
# A-M1: case-insensitive banned-key check
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize(
    "key",
    [
        "Email",
        "EMAIL",
        "User_Agent",
        "USER_AGENT",
        "Content",
        "Password",
        "PASSWORD_HASH",  # NEVER_EXEMPT base, mixed case
    ],
)
def test_is_banned_key_case_insensitive(key: str) -> None:
    """A-M1: mixed/upper-case keys must hit the same ban as lower-case.

    Without normalisation, ``Email`` would slip past the substring check
    against the lower-case BANNED_KEYS entries -- a silent privacy regression.
    """
    from gubbi_common.telemetry import is_banned_key

    assert is_banned_key(key), f"expected {key!r} banned via case-insensitive match"


@pytest.mark.unit
def test_is_banned_key_uppercase_derivative_still_exempt() -> None:
    """An uppercase derivative-suffix key on a non-NEVER-EXEMPT base is still exempt."""
    from gubbi_common.telemetry import is_banned_key

    # email_hash is exempt (email is not a NEVER_EXEMPT base, _hash is derivative).
    assert not is_banned_key("EMAIL_HASH")
    assert not is_banned_key("Body_Size")


# ===========================================================================
# Regression: content_hash must survive the substring check
# ===========================================================================


@pytest.mark.unit
def test_content_hash_is_not_banned() -> None:
    """``content_hash`` must pass the filter -- it is the audit-log dedup key.

    ``content`` is a BANNED_KEYS substring (raw journal content is never
    allowed in spans/metrics). ``content_hash`` is the sha256 digest used
    by the partial unique index ``audit_log_content_hash_uidx`` (gubbi
    migration 0020) and is structurally privacy-safe.

    Protection is structural via the ``_hash`` derivative-modifier
    suffix; this regression test pins it so a future tweak to
    DERIVATIVE_MODIFIERS or to the order-of-checks in ``is_banned_key``
    cannot silently start dropping the audit-dedup key.
    """
    from gubbi_common.telemetry import is_banned_key

    assert not is_banned_key("content_hash"), (
        "content_hash is the audit-log dedup key (mig 0020) and must "
        "survive BANNED_KEYS substring expansion via the _hash "
        "derivative-modifier exemption"
    )
    # Plain "content" remains banned -- the substring contract is intact.
    assert is_banned_key("content")
    # Case-insensitive variants must also survive.
    assert not is_banned_key("Content_Hash")
    assert not is_banned_key("CONTENT_HASH")
