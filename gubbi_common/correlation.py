"""Canonical correlation_id type + helpers for gubbi + gubbi-cloud.

Single source of truth across gubbi + gubbi-cloud. Instances of
:class:`CorrelationContext` flow through the gateway boundary
(``X-Correlation-ID`` header); per-process state is held in the
``correlation_id`` ContextVar exposed via
:func:`set_correlation_id` / :func:`get_correlation_id` /
:func:`reset_correlation_id` (re-exported here from
:mod:`gubbi_common.telemetry.logging` so consumers have one canonical
import point: ``from gubbi_common.correlation import ...``).

B5 Q1 (locked 2026-05-13): correlation_id canonical home is
gubbi-common. Both gubbi (MCP server) and gubbi-cloud (gateway) import
this module instead of redefining their own helpers. Mirrors the
existing canonical-in-gubbi-common patterns for XFF parsing
(``gubbi_common.http.client_ip``), audit ``Action`` enum, and the OTel
allowlist.

DO NOT extend :class:`CorrelationContext` without updating BOTH
consumers (gubbi + gubbi-cloud) and the doc on the gateway boundary
shape. The shape is a cross-repo contract -- adding a field on one
side without the other would silently divide the fleet.

Why a wrapper type when there's only one field today
-----------------------------------------------------
``CorrelationContext`` is intentionally a one-field frozen dataclass
rather than a bare ``str`` alias. It documents the boundary: the
correlation_id is the only piece of request-scoped context that crosses
the gateway envelope. Future additions (e.g. a parent-trace hint, an
upstream-deadline budget) would extend this type rather than smuggle a
new header through ad-hoc. YAGNI on extra fields today; the type
itself earns its keep by naming the contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from gubbi_common.telemetry.logging import (
    get_correlation_id,
    reset_correlation_id,
    set_correlation_id,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

# Lowercased ASGI header name; ASGI spec lowercases all header keys in
# the scope. Both consumers compare against this constant.
_CORRELATION_HEADER_BYTES: bytes = b"x-correlation-id"


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    """Request-scoped correlation envelope.

    Attributes:
        correlation_id: Opaque string identifier propagated as the
            ``X-Correlation-ID`` header through the gateway boundary.
            Validated on entry by
            :class:`gubbi_common.middleware.correlation.CorrelationIDMiddleware`
            (alphanumerics, dashes, underscores, dots; max 128 chars)
            with a UUID4 fallback when the inbound value is missing or
            invalid.

    The dataclass is ``frozen`` so instances are hashable and safe to
    pass through awaitables without accidental mutation. ``slots`` keeps
    the per-request allocation cheap.

    **Status (B5 R1, 2026-05-14): forward-compat shape.** Today's
    consumers (gubbi-cloud auth + subscription middleware) use
    ``cid_from_scope`` directly and pass the raw string through. The
    dataclass exists so future plumbing that wants typed propagation
    (e.g. a request-scoped contextvar carrying multiple correlation
    fields, or a shared ``CorrelationCarrier`` Protocol) has a single
    canonical home rather than re-shaping ad-hoc. Drop the dataclass
    if no consumer adopts it by 2026-Q3.
    """

    correlation_id: str


def cid_from_scope(scope: Mapping[str, Any]) -> str:
    """Extract ``X-Correlation-ID`` from an ASGI scope; return ``""`` if absent.

    Centralises the byte-iteration over ``scope["headers"]`` that
    gubbi-cloud's auth_middleware and subscription_middleware previously
    duplicated. The empty-string fallback (rather than ``None``) matches
    those callers' shape -- they treat the absence of a correlation_id
    as a soft signal, not an error.

    For consumers that want a populated fallback (UUID4 minting), use
    :class:`gubbi_common.middleware.correlation.CorrelationIDMiddleware`
    or call :func:`get_correlation_id` after the middleware has run.
    """
    headers = scope.get("headers", [])
    for key, val in headers:
        if key == _CORRELATION_HEADER_BYTES:
            try:
                decoded: str = val.decode("utf-8")
                return decoded
            except (UnicodeDecodeError, AttributeError):
                return ""
    return ""


__all__ = [
    "CorrelationContext",
    "cid_from_scope",
    "get_correlation_id",
    "reset_correlation_id",
    "set_correlation_id",
]
