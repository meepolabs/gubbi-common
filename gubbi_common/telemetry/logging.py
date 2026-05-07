"""Structured logging with JSON-per-line output and correlation/OTel helpers.

Promoted from gubbi + gubbi-cloud telemetry/logging modules into a
single canonical implementation in gubbi-common.

Public API::

    StructuredLogFormatter  -- logging.Formatter that emits one JSON line
                               per invocation.
    set_correlation_id / get_correlation_id  -- contextvar helpers.
    _get_otel_ids  -- (private) read trace/span IDs from OTel context.

Schema (one JSON object per line)::

    {
        "timestamp": <UTC ISO 8601 %Y-%m-%dT%H:%M:%S.%fZ>,
        "level": <levelname>,
        "service": <resolved service name>,
        "correlation_id": <string | null>,
        "trace_id": <hex string | null>,
        "span_id": <hex string | null>,
        "event": <event string>,
        "attributes": { ... }  -- omitted when empty and omit_empty_attributes=True
    }
"""

from __future__ import annotations

import json
import logging
import os
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Correlation ID context var
# ---------------------------------------------------------------------------

_correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

logger = logging.getLogger(__name__)


def set_correlation_id(cid: str) -> None:
    """Set the request-scoped correlation_id in context."""
    _correlation_id_var.set(cid)


def get_correlation_id() -> str | None:
    """Return the current request's correlation_id, or None."""
    return _correlation_id_var.get()


# ---------------------------------------------------------------------------
# OTel trace helpers (opentelemetry is optional -- consumers install it)
# ---------------------------------------------------------------------------


def _get_otel_ids() -> tuple[str | None, str | None]:
    """Return (trace_id_hex, span_id_hex) from the current OTel span, if any.

    Returns (None, None) when OpenTelemetry is not installed or no valid
    span context is active.
    """
    try:
        # Import here so gubbi-common works without opentelemetry installed;
        # consumers downstream (gubbi, gubbi-cloud) provide it.
        from opentelemetry import trace  # type: ignore[import-not-found]

        span = trace.get_current_span()
        span_context = span.get_span_context()
        if span_context and span_context.is_valid:
            trace_id_hex = format(span_context.trace_id, "032x")
            span_id_hex = format(span_context.span_id, "016x")
            return trace_id_hex, span_id_hex
    except Exception:
        logger.debug("Failed to read OTel span context", exc_info=True)
    return None, None


# ---------------------------------------------------------------------------
# stdlib LogRecord field names (for __dict__ exclusion in gubbi-mode)
# ---------------------------------------------------------------------------

_STDLIB_RECORD_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        # Python 3.14+ adds taskName (asyncio task context)
        "taskName",
    }
)


# ---------------------------------------------------------------------------
# StructuredLogFormatter
# ---------------------------------------------------------------------------


class StructuredLogFormatter(logging.Formatter):
    """JSON-per-line formatter with a stable schema.

    *Service name* defaults to ``os.environ["OTEL_SERVICE_NAME"]`` or
    ``"gubbi"``; pass ``service_name=...`` to override.

    *Attributes* are collected either by walking record.__dict__ (default,
    gubbi-mode) or by reading a named attribute on the record such as
    ``record.attributes_dict`` (cloud-mode via ``attributes_attr_name``).

    When ``dict_msg_attribute_key`` is set and ``record.msg`` is a dict,
    the dict is copied into *attributes* under that key for structlog
    interop.

    Usage::

        logger = logging.getLogger("gubbi")
        logger.info("tool.call", extra={"tool.name": "journal_append_entry"})

    This produces::

        {"timestamp": "2026-04-29T12:00:00Z", "level": "INFO",
         "service": "gubbi", "correlation_id": "...",
         "trace_id": "...", "span_id": "...",
         "event": "tool.call",
         "attributes": {"tool.name": "journal_append_entry"}}
    """

    def __init__(
        self,
        *,
        service_name: str | None = None,
        attributes_attr_name: str | None = None,
        dict_msg_attribute_key: str | None = None,
        omit_empty_attributes: bool = True,
        ensure_ascii: bool = False,
    ) -> None:
        super().__init__()
        self._service_name = (
            service_name
            if service_name is not None
            else os.environ.get("OTEL_SERVICE_NAME", "gubbi")
        )
        self._attributes_attr_name = attributes_attr_name
        self._dict_msg_attribute_key = dict_msg_attribute_key
        self._omit_empty_attributes = omit_empty_attributes
        self._ensure_ascii = ensure_ascii

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as a single JSON line."""
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Correlation/trace fallback chain: check record attrs first, then
        # contextvar / OTel.  This lets both gubbi (contextvar-driven) and
        # cloud (structlog-injected attrs) consumers work without extra kwargs.
        cid = getattr(record, "correlation_id", None) or get_correlation_id()

        rec_tid = getattr(record, "trace_id", None)
        rec_sid = getattr(record, "span_id", None)
        if rec_tid is None or rec_sid is None:
            ctx_tid, ctx_sid = _get_otel_ids()
            tid = rec_tid or ctx_tid
            sid = rec_sid or ctx_sid
        else:
            tid, sid = rec_tid, rec_sid

        # Attributes: two paths (record.__dict__ walk vs named attribute)
        if self._attributes_attr_name is not None:
            val = getattr(record, self._attributes_attr_name, None)
            attributes: dict[str, Any] = dict(val) if val is not None else {}
        else:
            attributes = {}
            for key, value in record.__dict__.items():
                if key in _STDLIB_RECORD_FIELDS:
                    continue
                attributes[key] = value

        # Dict-msg interop: copy record.msg dict into attributes under a key.
        if self._dict_msg_attribute_key is not None and isinstance(record.msg, dict):
            attributes.setdefault(self._dict_msg_attribute_key, record.msg)

        # Event derivation
        event = self._derive_event(record)

        entry: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "service": self._service_name,
            "correlation_id": cid,
            "trace_id": tid,
            "span_id": sid,
            "event": event,
        }

        if attributes or not self._omit_empty_attributes:
            entry["attributes"] = attributes

        return json.dumps(entry, default=str, ensure_ascii=self._ensure_ascii)

    # -----------------------------------------------------------------------
    # Helpers (split for testability / clarity)
    # -----------------------------------------------------------------------

    def _derive_event(self, record: logging.LogRecord) -> str:
        """Derive the human-readable event string from a LogRecord.

        Rules (in priority order):
        1. If ``record.msg`` is a dict -> ``record.getMessage()`` if
           formatable; otherwise stringify the dict.
        2. If ``record.args`` is non-empty -> ``record.getMessage()``
           (handles %-formatting).
        3. Otherwise -> ``record.msg`` (raw string).
        """
        if isinstance(record.msg, dict):
            try:
                return record.getMessage()
            except Exception:
                return json.dumps(record.msg, default=str)

        if record.args:
            try:
                return record.getMessage()
            except Exception:
                return str(record.msg)

        return str(record.msg)


__all__ = [
    "StructuredLogFormatter",
    "set_correlation_id",
    "get_correlation_id",
    "_get_otel_ids",
]
