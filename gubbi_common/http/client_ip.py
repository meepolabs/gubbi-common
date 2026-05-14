"""Client-IP extraction with safe-by-default trust-forwarded-headers semantics.

Locked by DEC-086. Callers MUST pass ``trust_forwarded_headers``
explicitly so the policy is per-call visible. Returns ``None`` when no
IP is recoverable.

Promoted from gubbi-cloud (``webhooks/kratos/_auth.py:_extract_client_ip``)
to close H-A4: gubbi's local copy at ``oauth/forms.py:client_ip`` had
silently regressed away from the rightmost X-Forwarded-For entry
(DEC-086 rule 4 violation -- it was reading the client-controllable
leftmost hop instead of the trusted-proxy stamp).
The correct implementation has been written multiple times and gotten
subtly wrong each time; one helper, byte-identical, signed-off in
DEC-086 prose, kills the recurrence.

DEC-086 rule 4: when a single trusted proxy fronts the app, the
RIGHTMOST X-Forwarded-For entry is the proxy-appended hop and is the
only one not controllable by the untrusted client. Reading the leftmost
entry lets a client spoof the source IP for any audit/log/rate-limit
keyed on it.
"""

from __future__ import annotations

import ipaddress
from typing import Protocol

__all__ = ["client_ip"]


class _HeadersLike(Protocol):
    """Minimal Mapping-shaped view of request headers.

    Starlette's ``Headers`` (case-insensitive multi-dict) satisfies this
    Protocol via ``.get(name)``. Tests pass a duck-typed shim with a
    matching ``get(key, /)`` signature. We do not require the full
    Mapping protocol because callers only ever read a single named header
    here.
    """

    def get(self, key: str, /) -> str | None: ...


class _ClientLike(Protocol):
    """Minimal Starlette ``request.client`` shape: a ``host`` attribute.

    Declared as a read-only ``@property`` so concrete implementations
    that expose ``host`` via either a plain attribute or an actual
    property both satisfy this Protocol structurally (Starlette's
    ``Address`` namedtuple uses the latter).
    """

    @property
    def host(self) -> str | None: ...


class _RequestLike(Protocol):
    """Narrow Protocol matching the slice of ``Request`` we read.

    ``headers`` and ``client`` are declared read-only via ``@property``
    so Starlette's ``starlette.requests.Request`` (which exposes both
    via ``@property``) satisfies the Protocol structurally under
    ``mypy --strict``. Test fakes that expose them as dataclass
    attributes also satisfy it (a settable attribute is a superset of
    a read-only one).
    """

    @property
    def headers(self) -> _HeadersLike: ...
    @property
    def client(self) -> _ClientLike | None: ...


def client_ip(request: _RequestLike, *, trust_forwarded_headers: bool) -> str | None:
    """Return the originating client IP per DEC-086 rule 4.

    When ``trust_forwarded_headers=True`` the RIGHTMOST X-Forwarded-For
    entry is treated as the trusted-proxy stamp. When ``False`` the XFF
    header is ignored and the socket address (``request.client.host``)
    is used directly.

    The candidate XFF entry is validated with ``ipaddress.ip_address``;
    a malformed value falls through to ``request.client.host`` instead
    of returning the bad string. Both IPv4 and IPv6 are accepted.

    Returns ``None`` when neither a valid trusted XFF entry nor a socket
    address is available. Callers decide how to render the empty case
    (gubbi uses the literal ``"unknown"`` for log-shape stability).

    Parameters
    ----------
    request:
        Anything with ``.headers`` (mapping with ``.get(name)``) and
        ``.client`` (object with ``.host`` or None). Starlette's
        ``Request`` satisfies this.
    trust_forwarded_headers:
        Keyword-only by design. Must be supplied per call so the
        policy is visible at the call site (DEC-086 rule).

    Returns
    -------
    str | None
        The originating client IP, or ``None`` if none is available.
    """
    if trust_forwarded_headers:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                candidate = parts[-1]
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    pass  # fall through to socket
                else:
                    return candidate
    if request.client is not None and request.client.host:
        # Validate the socket host the same way we validate XFF entries.
        # Starlette/uvicorn populate this from the ASGI ``server`` scope
        # key; in normal deployments it is always a valid IP. We still
        # validate here so a non-IP value (e.g. a hostname placed there
        # by a non-standard ASGI server or a test harness) cannot leak
        # into rate-limit keys, log lines, or audit rows.
        try:
            ipaddress.ip_address(request.client.host)
        except ValueError:
            return None
        return request.client.host
    return None
