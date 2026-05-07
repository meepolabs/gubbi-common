"""Canonical X-Correlation-ID extraction and propagation middleware.

Reconciled from gubbi + gubbi-cloud near-duplicate implementations.
Both consumers share the same core behaviour:

1. Read ``x-correlation-id`` from ASGI scope headers (byte-iteration).
2. Validate the raw value with a call-provided validator (default allows
   alphanumerics, dashes, underscores, and dots up to 128 characters).
3. Fall back to a fresh ``uuid4`` when no header or the value fails
   validation.
4. Set the correlation ID on a ContextVar via
   :func:`gubbi_common.telemetry.logging.set_correlation_id`.
5. Optionally echo the resolved ID back in the response headers
   (gubbi/MCP server sets ``echo_header=True``; gubbi-cloud/gateway
   sets ``False``).
6. Invoke a caller-supplied ``span_attribute_setter`` callback so each
   consumer can route through its own per-repo OTel allowlist without
   this module depending on OpenTelemetry directly.

``starlette`` provides the ASGI type imports used here and must be
installed by consumers as a peer dependency.
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping
from contextvars import Token
from typing import Any
from uuid import uuid4

from starlette.types import ASGIApp, Receive, Scope, Send

from gubbi_common.telemetry.logging import (
    reset_correlation_id,
    set_correlation_id,
)

HEADER_NAME_BYTES = b"x-correlation-id"
HEADER_NAME_STR = "X-Correlation-ID"


def _default_validator(value: str) -> bool:
    """Return True when *value* is non-empty and contains only safe chars.

    Allowed characters: alphanumerics, dash, underscore, period.
    Maximum length: 128 characters.
    """
    if not value or len(value) > 128:
        return False
    return all(c.isalnum() or c in "-_." for c in value)


class CorrelationIDMiddleware:
    """Extract/generate X-Correlation-ID; propagate via ContextVar.

    Args:
        app: downstream ASGI app.
        echo_header: if ``True``, the resolved correlation_id is echoed
            back in the response headers as ``X-Correlation-ID``.
            gubbi (MCP server) wants ``True``.  gubbi-cloud (upstream
            gateway) wants ``False`` -- downstream services own
            response echo.
        validator: optional caller-provided validator. If ``None``, the
            default validator accepts non-empty strings up to 128 chars
            consisting of alphanumerics plus ``-_.``. Invalid values
            trigger a UUID4 fallback.
        span_attribute_setter: optional callable invoked with the resolved
            correlation_id after the ContextVar is set. Per-repo callers
            wire this to their own ``safe_set_attributes()`` call so the
            per-repo OTel allowlist is honoured. If ``None``, no span
            attribute is set.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        echo_header: bool = True,
        validator: Callable[[str], bool] | None = None,
        span_attribute_setter: Callable[[str], None] | None = None,
    ) -> None:
        self.app = app
        self.echo_header = echo_header
        self.validator = _default_validator if validator is None else validator
        self.span_attribute_setter = span_attribute_setter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # ---- read header from ASGI scope (byte-iteration, cloud pattern)
        raw_cid: str | None = None
        for key, val in scope.get("headers", []):
            if key == HEADER_NAME_BYTES:
                try:
                    raw_cid = val.decode("ascii").strip()
                except (UnicodeDecodeError, AttributeError):
                    raw_cid = None
                break

        # ---- validate + fallback to UUID4
        cid = raw_cid if raw_cid and self.validator(raw_cid) else str(uuid4())

        # ---- set ContextVar via gubbi-common API
        token: Token[str | None] = set_correlation_id(cid)

        try:
            # ---- per-repo span attribute injection (OTel-agnostic)
            if self.span_attribute_setter is not None:
                self.span_attribute_setter(cid)

            # ---- wrap *send* to echo the header in responses
            if self.echo_header:
                send_wrapper = _make_echo_send(send, HEADER_NAME_STR, cid)
                await self.app(scope, receive, send_wrapper)
            else:
                await self.app(scope, receive, send)
        finally:
            reset_correlation_id(token)


def _make_echo_send(
    send: Send,
    header_name: str,
    value: str,
) -> Send:
    """Return a *send* wrapper that injects **header_name** / **value**.

    The wrapper fires the parent ``send`` with the header patch after
    reconstructing the message envelope.
    """

    header_name_bytes = header_name.encode("ascii")
    header_name_lower = header_name_bytes.lower()

    async def wrapped(message: MutableMapping[str, Any]) -> None:
        if message["type"] == "http.response.start":
            headers = message.get("headers", [])
            # ASGI headers are list of (name-bytes, value-bytes) tuples
            patched_headers: list[tuple[bytes, bytes]] = []
            for k, v in headers:
                if k.lower() != header_name_lower:
                    patched_headers.append((k, v))
            # Replace any existing correlation-id header with this value.
            patched_headers.append((header_name_bytes, value.encode("ascii")))
            message = {**message, "headers": patched_headers}
        await send(message)

    return wrapped
