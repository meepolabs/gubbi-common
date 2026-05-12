"""Tests for ``gubbi_common.http.client_ip``.

Locks the DEC-086 rule 4 invariant (rightmost X-Forwarded-For when
trusted) and the safe-by-default fallback shape. Promoted from the
cloud-side ``_extract_client_ip`` parametrization so both consumer
repos share a single regression suite.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from gubbi_common.http.client_ip import client_ip


@dataclass
class _FakeClient:
    host: str | None


class _FakeHeaders:
    """Minimal headers shim with ``.get(name)``; case-insensitive lookup."""

    def __init__(self, items: dict[str, str] | None = None) -> None:
        self._items = {k.lower(): v for k, v in (items or {}).items()}

    def get(self, key: str, /) -> str | None:
        return self._items.get(key.lower())


@dataclass
class _FakeRequest:
    headers: _FakeHeaders
    client: _FakeClient | None


def _make_request(
    *,
    xff: str | None = None,
    client_host: str | None = "127.0.0.1",
) -> _FakeRequest:
    headers = _FakeHeaders({"x-forwarded-for": xff} if xff is not None else None)
    client = _FakeClient(host=client_host) if client_host is not None else None
    return _FakeRequest(headers=headers, client=client)


@pytest.mark.unit
def test_returns_rightmost_xff_when_trusted() -> None:
    """DEC-086 rule 4: the trusted-proxy stamp is the RIGHTMOST entry."""
    req = _make_request(xff="1.2.3.4, 5.6.7.8, 9.10.11.12", client_host="10.0.0.1")
    assert client_ip(req, trust_forwarded_headers=True) == "9.10.11.12"


@pytest.mark.unit
def test_falls_back_when_xff_invalid() -> None:
    """A malformed rightmost entry falls through to ``request.client.host``."""
    req = _make_request(xff="1.2.3.4, not-an-ip", client_host="10.0.0.1")
    assert client_ip(req, trust_forwarded_headers=True) == "10.0.0.1"


@pytest.mark.unit
def test_ignores_xff_when_untrusted() -> None:
    """trust_forwarded_headers=False ignores XFF entirely (socket only)."""
    req = _make_request(xff="1.2.3.4, 9.10.11.12", client_host="10.0.0.1")
    assert client_ip(req, trust_forwarded_headers=False) == "10.0.0.1"


@pytest.mark.unit
def test_returns_none_when_no_source() -> None:
    """No XFF and no socket -> None (caller picks the rendered sentinel)."""
    req = _make_request(xff=None, client_host=None)
    assert client_ip(req, trust_forwarded_headers=True) is None
    assert client_ip(req, trust_forwarded_headers=False) is None


@pytest.mark.unit
def test_handles_ipv6_xff() -> None:
    """IPv6 entries (with or without zone IDs) parse via ``ipaddress.ip_address``."""
    req = _make_request(xff="1.2.3.4, 2001:db8::1", client_host="10.0.0.1")
    assert client_ip(req, trust_forwarded_headers=True) == "2001:db8::1"


@pytest.mark.unit
def test_empty_xff_falls_back_to_socket() -> None:
    """Empty XFF header (whitespace-only) falls through to socket."""
    req = _make_request(xff="   ", client_host="10.0.0.1")
    assert client_ip(req, trust_forwarded_headers=True) == "10.0.0.1"


@pytest.mark.unit
def test_xff_with_trailing_comma_uses_rightmost_real_entry() -> None:
    """Trailing comma + space is a no-op; rightmost real entry wins."""
    req = _make_request(xff="1.2.3.4, 9.10.11.12,", client_host="10.0.0.1")
    assert client_ip(req, trust_forwarded_headers=True) == "9.10.11.12"


@pytest.mark.unit
def test_xff_present_but_client_none_returns_xff() -> None:
    """XFF still wins when ``request.client`` is None."""
    req = _make_request(xff="9.10.11.12", client_host=None)
    assert client_ip(req, trust_forwarded_headers=True) == "9.10.11.12"


@pytest.mark.unit
def test_xff_invalid_and_client_none_returns_none() -> None:
    """Invalid XFF + no socket -> None (no fallback to the bad string)."""
    req = _make_request(xff="not-an-ip", client_host=None)
    assert client_ip(req, trust_forwarded_headers=True) is None
