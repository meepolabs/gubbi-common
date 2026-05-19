"""Auto-inject ``correlation_id`` on every OTel span at span-start.

A :class:`CorrelationSpanProcessor` reads ``correlation_id`` from the
ContextVar populated by :class:`gubbi_common.middleware.CorrelationIDMiddleware`
on every inbound HTTP request and stamps it onto each span as it opens.
Bypasses the per-span attribute allowlists in consumer repos because
attribute filtering only applies to ``safe_set_attributes`` -- direct
``span.set_attribute`` calls (which is what this processor does) land
unconditionally.

Registered by passing an instance to
:func:`gubbi_common.telemetry.otel.configure_otel` via the
``extra_processors`` arg, so the wiring is atomic with provider
construction (no "register-after-configure" foot-gun where a gap window
emits un-tagged spans).

Out-of-request spans (Arq workers, lifespan startup tasks, orphan
cleanup) see ``get_correlation_id() is None`` and are left untagged. A
synthetic sentinel would pollute forensic queries -- the per-job
correlation_id minting strategy for background work is a separate
decision tracked outside this module.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentelemetry.sdk.trace import SpanProcessor

from gubbi_common.correlation import get_correlation_id

if TYPE_CHECKING:
    from opentelemetry.context import Context
    from opentelemetry.sdk.trace import ReadableSpan, Span

__all__ = ["CorrelationSpanProcessor"]

_CORRELATION_ATTR: str = "correlation_id"


class CorrelationSpanProcessor(SpanProcessor):
    """SpanProcessor that injects ``correlation_id`` at span-start.

    Reads from the ContextVar exposed by ``gubbi_common.correlation``.
    Skips silently when the ContextVar is unset (background tasks,
    lifespan startup) so those spans remain untagged rather than
    carrying a misleading sentinel.
    """

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        """Attach correlation_id to the span if a request-scoped value is set."""
        cid = get_correlation_id()
        if cid is None:
            return
        span.set_attribute(_CORRELATION_ATTR, cid)

    def on_end(self, span: ReadableSpan) -> None:
        """No-op: this processor only acts at span open."""

    def shutdown(self) -> None:
        """No-op: this processor holds no resources."""

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        """No-op: this processor has no buffered state to flush."""
        return True
