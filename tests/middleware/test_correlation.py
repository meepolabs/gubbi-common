"""Unit tests for gubbi_common.middleware.CorrelationIDMiddleware.

Covers all kwarg branches: echo_header, validator, span_attribute_setter,
and default header-extraction / UUID4-fallback behaviour.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import pytest

from gubbi_common.middleware.correlation import (
    CorrelationIDMiddleware,
    _default_validator,
)
from gubbi_common.telemetry.logging import get_correlation_id

# ---------------------------------------------------------------------------
# Hand-rolled ASGI harness
# ---------------------------------------------------------------------------


def _reset_cid() -> None:
    """Reset the correlation ContextVar to its default."""
    from gubbi_common.telemetry import logging as log_mod  # noqa: PLC0415

    log_mod._correlation_id_var.set(None)  # type: ignore[union-attr]


class _CaptureApp:
    """ASGI app that captures the CID via ContextVar before returning.

    The middleware sets the CID in a ContextVar BEFORE forwarding to this
    inner app, so reading get_correlation_id() here is safe.
    """

    def __init__(self) -> None:
        self.captured_cid: str | None = None
        self.headers_response: list[dict[str, Any]] = []

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,  # noqa: ANN201
    ) -> None:
        self.captured_cid = get_correlation_id()
        # Also let the response echo tests work by calling send through
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


class _EchoApp:
    """Minimal ASGI app that echoes a response (no CID capture)."""

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,  # noqa: ANN201
    ) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


class _ExistingHeaderApp:
    """ASGI app that emits an existing X-Correlation-ID header."""

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,  # noqa: ANN201
    ) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"x-correlation-id", b"downstream-value")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})


class Sender:
    """Hand-rolled ASGI send-message collector."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def __call__(self, message: dict[str, Any]) -> None:
        self.messages.append(message)

    def get_header(self, name: str) -> bytes | None:
        """Return *value-bytes* for *name* from response headers."""
        low = name.lower()
        for msg in self.messages:
            if msg["type"] == "http.response.start":
                for hdr_name, hdr_val in msg.get("headers", []):
                    if hdr_name.decode("ascii").lower() == low:
                        return hdr_val
        return None


async def _run_middleware(
    middleware: CorrelationIDMiddleware,
    scope_headers: list[tuple[bytes, bytes]] | None = None,
) -> Sender:
    """Invoke *middleware* and collect response messages.

    Returns the Sender so headers can be inspected.
    """
    sender = Sender()
    await middleware(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": scope_headers or [],
        },
        lambda: {},
        sender,
    )
    return sender


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_header_passed_through_when_present() -> None:
    """X-Correlation-ID header is extracted and set on the ContextVar."""
    cid_value = "req-abc-123"
    captured_cid: list[str | None] = [None]

    def capture(cid: str) -> None:
        captured_cid[0] = cid

    app = _CaptureApp()
    middleware = CorrelationIDMiddleware(
        app,
        span_attribute_setter=capture,
    )

    await middleware(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-correlation-id", b"req-abc-123")],
        },
        lambda: {},
        Sender(),
    )

    assert captured_cid[0] == cid_value


@pytest.mark.asyncio
async def test_uuid4_fallback_when_header_absent() -> None:
    """Without the header a UUID4 is generated and set on the ContextVar."""
    uuid4_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    captured_cid: list[str | None] = [None]

    def capture(cid: str) -> None:
        captured_cid[0] = cid

    app = _EchoApp()
    middleware = CorrelationIDMiddleware(app, span_attribute_setter=capture)

    await middleware(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
        },
        lambda: {},
        Sender(),
    )

    assert captured_cid[0] is not None
    assert uuid4_pattern.match(captured_cid[0]), f"Expected UUID4, got {captured_cid[0]!r}"


@pytest.mark.asyncio
async def test_validator_rejects_forces_uuid4_fallback() -> None:
    """A validator that always returns False forces UUID4 fallback."""
    uuid4_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    captured_cid: list[str | None] = [None]

    def capture(cid: str) -> None:
        captured_cid[0] = cid

    app = _EchoApp()
    middleware = CorrelationIDMiddleware(
        app,
        validator=lambda _: False,
        span_attribute_setter=capture,
    )

    await middleware(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-correlation-id", b"some-value")],
        },
        lambda: {},
        Sender(),
    )

    assert captured_cid[0] is not None
    assert uuid4_pattern.match(captured_cid[0]), f"Expected UUID4 fallback, got {captured_cid[0]!r}"


@pytest.mark.asyncio
async def test_echo_header_true_response_contains_cid() -> None:
    """When echo_header=True the response carries X-Correlation-ID."""
    app = _EchoApp()

    sender = await _run_middleware(
        CorrelationIDMiddleware(app, echo_header=True),
        scope_headers=[(b"x-correlation-id", b"echo-cid-value")],
    )

    raw_value = sender.get_header("x-correlation-id")
    assert raw_value is not None
    assert raw_value == b"echo-cid-value"


@pytest.mark.asyncio
async def test_echo_header_replaces_existing_response_header() -> None:
    """Middleware replaces any downstream X-Correlation-ID header."""
    sender = await _run_middleware(
        CorrelationIDMiddleware(_ExistingHeaderApp(), echo_header=True),
        scope_headers=[(b"x-correlation-id", b"echo-cid-value")],
    )

    start_messages = [msg for msg in sender.messages if msg["type"] == "http.response.start"]
    headers = start_messages[0]["headers"]

    assert sum(1 for name, _ in headers if name.lower() == b"x-correlation-id") == 1
    assert b"downstream-value" not in [value for _, value in headers]


@pytest.mark.asyncio
async def test_echo_header_false_response_lacks_cid() -> None:
    """When echo_header=False the response does NOT carry X-Correlation-ID."""
    app = _EchoApp()

    sender = await _run_middleware(
        CorrelationIDMiddleware(app, echo_header=False),
        scope_headers=[(b"x-correlation-id", b"nosend")],
    )

    assert sender.get_header("x-correlation-id") is None


@pytest.mark.asyncio
async def test_span_attribute_setter_called_with_resolved_cid() -> None:
    """span_attribute_setter receives the final correlation_id."""
    captured: list[str] = []

    def setter(cid: str) -> None:
        captured.append(cid)

    app = _EchoApp()

    await _run_middleware(
        CorrelationIDMiddleware(app, span_attribute_setter=setter),
        scope_headers=[(b"x-correlation-id", b"span-cid-99")],
    )

    assert captured == ["span-cid-99"]


# ---------------------------------------------------------------------------
# _default_validator helpers / unit tests
# ---------------------------------------------------------------------------


def test_default_validator_accepts_alphanum_dash_dot() -> None:
    """Default validator accepts alphanumerics plus -, _, and .."""
    assert _default_validator("abc-123.XYZ") is True
    assert _default_validator("foo_bar") is True
    assert _default_validator("valid.id-here") is True


def test_default_validator_rejects_empty_too_long_special_chars() -> None:
    """Default validator rejects empty, >128 chars, and non-allowed chars."""
    assert _default_validator("") is False
    assert _default_validator("a" * 129) is False
    assert _default_validator("hello!world") is False


@pytest.mark.asyncio
async def test_valid_header_passes_default_validator() -> None:
    """A valid header value passes the default validator as-is."""
    captured_cid: list[str | None] = [None]

    def capture(cid: str) -> None:
        captured_cid[0] = cid

    _reset_cid()
    middleware = CorrelationIDMiddleware(
        _CaptureApp(),
        span_attribute_setter=capture,
    )

    await middleware(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-correlation-id", b"valid_cid-value.test")],
        },
        lambda: {},
        Sender(),
    )

    assert captured_cid[0] == "valid_cid-value.test"


@pytest.mark.asyncio
async def test_contextvar_reset_in_finally_block() -> None:
    """After the middleware returns ContextVar is reset to default (None)."""
    _reset_cid()
    middleware = CorrelationIDMiddleware(_EchoApp())

    await middleware(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-correlation-id", b"temp-cid")],
        },
        lambda: {},
        Sender(),
    )

    assert get_correlation_id() is None
