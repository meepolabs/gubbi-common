"""Tests for the unified ``build_bearer_challenge`` helper."""

from __future__ import annotations

import re

import pytest

from gubbi_common.auth.bearer_challenge import build_bearer_challenge


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
