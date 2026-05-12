"""Tests for ``gubbi_common.auth.prm.build_prm_metadata_url``.

Locks the contract for RFC 9728 PRM metadata URL composition that both
cloud-api and gubbi consume. The four parametrized cases mirror the
architect doc H-A3 test plan; ``test_self_host_shape`` covers the gubbi
self-host path-prefix shape.
"""

from __future__ import annotations

import pytest

from gubbi_common.auth.prm import PRMUrlError, build_prm_metadata_url


@pytest.mark.unit
@pytest.mark.parametrize(
    "resource_url",
    [
        "https://mcp.gubbi.ai",
        "https://mcp.gubbi.ai/",
    ],
)
def test_builds_legacy_form(resource_url: str) -> None:
    """legacy_suffix=True (default) appends ``/mcp`` after the canonical path."""
    out = build_prm_metadata_url(resource_url, legacy_suffix=True)
    assert out == "https://mcp.gubbi.ai/.well-known/oauth-protected-resource/mcp"


@pytest.mark.unit
def test_builds_legacy_form_default_arg() -> None:
    """``legacy_suffix`` defaults to True for DEC-083 cutover compat."""
    out = build_prm_metadata_url("https://mcp.gubbi.ai")
    assert out == "https://mcp.gubbi.ai/.well-known/oauth-protected-resource/mcp"


@pytest.mark.unit
def test_builds_canonical_form() -> None:
    """legacy_suffix=False returns the bare RFC 9728 canonical path."""
    out = build_prm_metadata_url("https://mcp.gubbi.ai", legacy_suffix=False)
    assert out == "https://mcp.gubbi.ai/.well-known/oauth-protected-resource"


@pytest.mark.unit
def test_normalizes_trailing_slash() -> None:
    """Trailing slashes on ``resource_url`` collapse: only origin contributes."""
    with_slash = build_prm_metadata_url("https://mcp.gubbi.ai/", legacy_suffix=True)
    without_slash = build_prm_metadata_url("https://mcp.gubbi.ai", legacy_suffix=True)
    assert with_slash == without_slash


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_url",
    [
        "/mcp",  # relative path -- no scheme, no netloc
        "mcp.gubbi.ai",  # bare host -- no scheme
        "",  # empty
        "ftp://mcp.gubbi.ai",  # wrong scheme
    ],
)
def test_rejects_relative_url(bad_url: str) -> None:
    """Non-absolute or non-http(s) URLs raise PRMUrlError."""
    with pytest.raises(PRMUrlError):
        build_prm_metadata_url(bad_url)


@pytest.mark.unit
def test_self_host_shape() -> None:
    """gubbi self-host shape: path on resource_url is discarded; origin only."""
    out = build_prm_metadata_url("https://localhost:8100/mcp", legacy_suffix=True)
    assert out == "https://localhost:8100/.well-known/oauth-protected-resource/mcp"


@pytest.mark.unit
def test_prm_url_error_subclasses_value_error() -> None:
    """PRMUrlError is a ValueError so callers can catch either."""
    assert issubclass(PRMUrlError, ValueError)


@pytest.mark.unit
def test_strips_userinfo_credentials() -> None:
    """user:pass@host in resource_url is stripped before the origin lands.

    PRM URLs flow into WWW-Authenticate challenges, discovery JSON, and
    OAuth audience claims -- any of which may be logged or returned to
    untrusted clients. Per RFC 6454, origin is ``scheme://host[:port]``;
    userinfo is explicitly excluded.
    """
    out = build_prm_metadata_url("https://user:secret@mcp.gubbi.ai/path", legacy_suffix=True)
    assert out == "https://mcp.gubbi.ai/.well-known/oauth-protected-resource/mcp"
    assert "user" not in out
    assert "secret" not in out


@pytest.mark.unit
def test_preserves_explicit_port() -> None:
    """An explicit port on the resource_url is preserved in the output origin."""
    out = build_prm_metadata_url("https://mcp.gubbi.ai:8443", legacy_suffix=False)
    assert out == "https://mcp.gubbi.ai:8443/.well-known/oauth-protected-resource"


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_url",
    [
        "https://mcp.gubbi.ai:99999",  # port > 65535
        "https://mcp.gubbi.ai:abc",  # non-numeric port
    ],
)
def test_rejects_malformed_port(bad_url: str) -> None:
    """Malformed ports raise PRMUrlError, not bare ValueError.

    ``urllib.parse.urlparse(...).port`` raises ValueError for these
    inputs; the helper wraps so callers catching PRMUrlError do not
    miss them.
    """
    with pytest.raises(PRMUrlError):
        build_prm_metadata_url(bad_url)
