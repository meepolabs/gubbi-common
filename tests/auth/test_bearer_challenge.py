"""Tests for the unified ``build_bearer_challenge`` helper."""

from __future__ import annotations

import re

import pytest

from gubbi_common.auth.bearer_challenge import build_bearer_challenge

# ===========================================================================
# Happy paths (existing contract)
# ===========================================================================


@pytest.mark.unit
def test_no_credentials_path_includes_only_resource_metadata() -> None:
    # RFC 6750 sec 3: omit error= when no auth was attempted.
    out = build_bearer_challenge(resource_metadata_url="/.well-known/oauth-protected-resource")
    assert out == 'Bearer resource_metadata="/.well-known/oauth-protected-resource"'
    assert "error=" not in out


@pytest.mark.unit
def test_invalid_token_path_includes_error() -> None:
    out = build_bearer_challenge(
        error="invalid_token",
        resource_metadata_url="/.well-known/oauth-protected-resource",
    )
    assert out == (
        'Bearer error="invalid_token", ' 'resource_metadata="/.well-known/oauth-protected-resource"'
    )


@pytest.mark.unit
def test_insufficient_scope_path_includes_required_scope() -> None:
    out = build_bearer_challenge(
        error="insufficient_scope",
        resource_metadata_url="/.well-known/oauth-protected-resource",
        required_scope="journal:write",
    )
    # required_scope appears between error and resource_metadata
    assert out == (
        'Bearer error="insufficient_scope", '
        'required_scope="journal:write", '
        'resource_metadata="/.well-known/oauth-protected-resource"'
    )


@pytest.mark.unit
def test_required_scope_without_error_is_supported() -> None:
    out = build_bearer_challenge(
        resource_metadata_url="/.well-known/oauth-protected-resource",
        required_scope="journal:write",
    )
    assert (
        out == 'Bearer required_scope="journal:write", '
        'resource_metadata="/.well-known/oauth-protected-resource"'
    )


@pytest.mark.unit
def test_absolute_resource_metadata_url() -> None:
    """Cloud-api may pass absolute URLs; journalctl typically passes relative."""
    out = build_bearer_challenge(
        error="invalid_token",
        resource_metadata_url="https://api.example.com/.well-known/oauth-protected-resource",
    )
    assert 'resource_metadata="https://api.example.com/' in out


@pytest.mark.unit
def test_no_resource_metadata_omits_the_parameter() -> None:
    out = build_bearer_challenge(error="invalid_token")
    assert out == 'Bearer error="invalid_token"'


@pytest.mark.unit
def test_all_omitted_returns_bare_bearer() -> None:
    """Defensive: empty challenge still parses as a Bearer scheme name."""
    out = build_bearer_challenge()
    assert out == "Bearer"


@pytest.mark.unit
def test_output_matches_rfc_6750_format() -> None:
    """Spot-check format: scheme + space + comma-separated key="value"."""
    out = build_bearer_challenge(
        error="invalid_token",
        resource_metadata_url="/.well-known/x",
        required_scope="journal",
    )
    # auth-scheme = "Bearer"
    assert out.startswith("Bearer ")
    # parameter list is `<key>="<value>"(, <key>="<value>")*`
    params = out[len("Bearer ") :]
    pattern = re.compile(r'^[a-z_]+="[^"]+"(, [a-z_]+="[^"]+")*$')
    assert pattern.match(params), f"unexpected format: {params!r}"


@pytest.mark.unit
def test_parameter_order_is_stable() -> None:
    """error first, then required_scope, then resource_metadata."""
    out = build_bearer_challenge(
        error="insufficient_scope",
        required_scope="journal:write",
        resource_metadata_url="/x",
    )
    error_idx = out.index('error="')
    scope_idx = out.index('required_scope="')
    rm_idx = out.index('resource_metadata="')
    assert error_idx < scope_idx < rm_idx


# ===========================================================================
# Header-injection rejection -- forbidden characters (C-8)
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_char",
    ["\r", "\n", "\x00", "\t", "\x1f", "\x7f"],
    ids=["CR", "LF", "NUL", "HTAB", "US", "DEL"],
)
def test_forbidden_control_chars_in_error_rejected(bad_char: str) -> None:
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(error=f"invalid{bad_char}token")


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_char",
    ["\r", "\n", "\x00"],
    ids=["CR", "LF", "NUL"],
)
def test_forbidden_control_chars_in_required_scope_rejected(bad_char: str) -> None:
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(required_scope=f"journal{bad_char}write")


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_char",
    ["\r", "\n", "\x00"],
    ids=["CR", "LF", "NUL"],
)
def test_forbidden_control_chars_in_resource_metadata_rejected(bad_char: str) -> None:
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(resource_metadata_url=f"/.well-known{bad_char}foo")


@pytest.mark.unit
def test_double_quote_in_error_rejected() -> None:
    """Quote injection: error='invalid", malicious="x' must not be possible."""
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(error='invalid", malicious="x')


@pytest.mark.unit
def test_double_quote_in_required_scope_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(required_scope='journal", malicious="x')


@pytest.mark.unit
def test_double_quote_in_resource_metadata_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(resource_metadata_url='/foo", malicious="x')


@pytest.mark.unit
def test_backslash_in_error_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(error="bad\\token")


@pytest.mark.unit
def test_backslash_in_required_scope_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(required_scope="bad\\scope")


@pytest.mark.unit
def test_backslash_in_resource_metadata_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden character"):
        build_bearer_challenge(resource_metadata_url="/foo\\bar")


# ===========================================================================
# Header-injection rejection -- grammar violations (C-8)
# ===========================================================================


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_error",
    [
        "invalid token",  # space disallowed in token
        "(comment)",  # parens disallowed
        "with,comma",  # comma disallowed
        "with;semi",  # semicolon disallowed
        "",  # empty -- token is 1*tchar
    ],
)
def test_invalid_error_grammar_rejected(bad_error: str) -> None:
    with pytest.raises(ValueError, match="RFC 7230 token"):
        build_bearer_challenge(error=bad_error)


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_scope",
    [
        "",  # empty -- scope is 1*scope-token
        " journal:write",  # leading space (scope-token has no leading SP)
        "journal:write ",  # trailing space
        "journal:write  another",  # double space between tokens
        "scope\xe9",  # non-ASCII -- outside scope-token grammar
    ],
)
def test_invalid_required_scope_grammar_rejected(bad_scope: str) -> None:
    with pytest.raises(ValueError, match="RFC 6749 scope grammar"):
        build_bearer_challenge(required_scope=bad_scope)


@pytest.mark.unit
def test_resource_metadata_url_must_start_with_slash_or_https() -> None:
    with pytest.raises(ValueError, match="must start with"):
        build_bearer_challenge(resource_metadata_url="example.com/foo")


@pytest.mark.unit
def test_resource_metadata_url_http_rejected() -> None:
    """HTTP is not accepted -- the OAuth metadata document must be fetched over TLS."""
    with pytest.raises(ValueError, match="must start with"):
        build_bearer_challenge(resource_metadata_url="http://example.com/foo")


@pytest.mark.unit
def test_relative_resource_metadata_accepted() -> None:
    out = build_bearer_challenge(resource_metadata_url="/.well-known/oauth-protected-resource")
    assert 'resource_metadata="/.well-known/oauth-protected-resource"' in out


@pytest.mark.unit
def test_https_resource_metadata_accepted() -> None:
    out = build_bearer_challenge(resource_metadata_url="https://example.com/.well-known/x")
    assert 'resource_metadata="https://example.com/.well-known/x"' in out


@pytest.mark.unit
def test_multi_scope_required_scope_accepted() -> None:
    """RFC 6749 allows space-separated scope-tokens."""
    out = build_bearer_challenge(required_scope="journal:read journal:write")
    assert 'required_scope="journal:read journal:write"' in out
