"""Structured logging with JSON-per-line output and correlation/OTel helpers.

Promoted from gubbi + gubbi-cloud telemetry/logging modules into a
single canonical implementation in gubbi-common.

Public API::

    StructuredLogFormatter  -- logging.Formatter that emits one JSON line
                               per invocation.
    set_correlation_id / get_correlation_id  -- contextvar helpers.

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
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from logging import handlers
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

# ---------------------------------------------------------------------------
# Correlation ID context var
# ---------------------------------------------------------------------------

_correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

logger = logging.getLogger(__name__)


def set_correlation_id(cid: str) -> Token[str | None]:
    """Set the request-scoped correlation_id in context.

    Returns a ``Token`` that ASGI/scope-bound callers should pass to
    ``reset_correlation_id`` in a ``finally`` block to restore the prior
    value, preventing cross-request leakage. Callers that don't need
    reset semantics may discard the return value.
    """
    return _correlation_id_var.set(cid)


def reset_correlation_id(token: Token[str | None]) -> None:
    """Reset the correlation_id ContextVar to its prior value.

    Pair with ``set_correlation_id``; pass the returned ``Token``.
    """
    _correlation_id_var.reset(token)


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
        from opentelemetry import trace

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
        # Injected by Formatter.format() / Formatter.formatTime() when an
        # earlier handler/formatter runs on the same record before us.
        "message",
        "asctime",
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

        # Correlation/trace fallback chain: check record attrs first (only
        # falling back when the attr is literally missing or None), then
        # contextvar / OTel. Truthiness fallback (`or`) would treat an
        # intentionally provided empty string as missing; we use explicit
        # `is None` checks instead so callers retain control over empty
        # values. This lets both gubbi (contextvar-driven) and cloud
        # (structlog-injected attrs) consumers work without extra kwargs.
        rec_cid = getattr(record, "correlation_id", None)
        cid = rec_cid if rec_cid is not None else get_correlation_id()

        rec_tid = getattr(record, "trace_id", None)
        rec_sid = getattr(record, "span_id", None)
        if rec_tid is None or rec_sid is None:
            ctx_tid, ctx_sid = _get_otel_ids()
            tid = rec_tid if rec_tid is not None else ctx_tid
            sid = rec_sid if rec_sid is not None else ctx_sid
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
        # Take a shallow copy so subsequent mutations to record.msg by the
        # caller don't retroactively change the formatted output.
        if self._dict_msg_attribute_key is not None and isinstance(record.msg, dict):
            attributes.setdefault(self._dict_msg_attribute_key, dict(record.msg))

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


# ---------------------------------------------------------------------------
# Shared processors (port of gubbi.core.logger)
# ---------------------------------------------------------------------------

LOG_ROTATE_WHEN: str = os.getenv(key="LOG_ROTATE_WHEN", default="W6")
LOG_ROTATE_BACKUP: int = int(os.getenv(key="LOG_ROTATE_BACKUP", default="4"))


def _safe_add_logger_name(
    logger: WrappedLogger,
    method: str,
    event_dict: EventDict,
) -> EventDict:
    """Like structlog.stdlib.add_logger_name but handles None logger.

    The MCP SDK's internal loggers pass records through the
    ProcessorFormatter where the logger reference can be None,
    causing the standard add_logger_name to crash with
    AttributeError: 'NoneType' object has no attribute 'name'.
    """
    record = event_dict.get("_record")
    if record is not None:
        event_dict["logger"] = record.name
    elif logger is not None:
        event_dict["logger"] = getattr(logger, "name", "unknown")
    else:
        event_dict["logger"] = "unknown"
    return event_dict


def _add_otel_context(
    logger: WrappedLogger,
    method: str,
    event_dict: EventDict,
) -> EventDict:
    """Enrich log events with correlation_id, trace_id, and span_id.

    Reads the current OTel span context and the ``correlation_id``
    context var from this module, adding them to every log event.
    """
    cid = get_correlation_id()
    if cid is not None:
        event_dict["correlation_id"] = cid

    try:
        span = trace_get_current_span()
        span_context = span.get_span_context()
        if span_context and span_context.is_valid:
            event_dict["trace_id"] = format(span_context.trace_id, "032x")
            event_dict["span_id"] = format(span_context.span_id, "016x")
    except Exception:
        logger.debug("Failed to read OTel span context for log enrichment", exc_info=True)

    event_dict["service"] = os.environ.get("OTEL_SERVICE_NAME", "gubbi")
    return event_dict


# Lazy-import wrapper so the module loads without opentelemetry installed.
def trace_get_current_span() -> Any:
    """Import-only lazy access to OTel's get_current_span."""
    from opentelemetry import trace

    return trace.get_current_span()


# Shared processors used by both structlog and ProcessorFormatter
_SHARED_PROCESSORS: list[structlog.types.Processor] = [
    _safe_add_logger_name,
    _add_otel_context,
    structlog.stdlib.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.UnicodeDecoder(),
    structlog.processors.JSONRenderer(),
]


def initialize_logger(logger_name: str, log_dir: str = "logs") -> structlog.stdlib.BoundLogger:
    """Initialize structured logging for the application.

    Sets up a ProcessorFormatter on the file handler so that ALL
    loggers (both structlog and plain stdlib) produce consistent
    JSON output.  This means modules can safely use either:

        # Async context (main.py, lifespan):
        logger = structlog.get_logger("gubbi")
        logger.info("event", key=value)

        # Sync (storage, oauth):
        logger = logging.getLogger("gubbi.oauth.login")
        logger.info("event", extra={"key": value})

    Args:
        logger_name: Name of the logger and log file.
        log_dir: Directory for log files.

    Returns:
        A ``structlog.stdlib.BoundLogger`` (the cached configured logger).
    """
    os.makedirs(log_dir, exist_ok=True)

    # File handler with rotation
    log_file_path = f"{log_dir}/{logger_name}.log"
    file_handler = handlers.TimedRotatingFileHandler(
        filename=log_file_path,
        when=LOG_ROTATE_WHEN,
        backupCount=LOG_ROTATE_BACKUP,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.INFO)

    # ProcessorFormatter: renders ALL stdlib log records through
    # structlog processors, producing consistent JSON output
    fmt = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            *_SHARED_PROCESSORS,
        ],
    )
    file_handler.setFormatter(fmt)

    # Attach handler directly to root so we bypass basicConfig gating.
    root = logging.getLogger()
    if not any(isinstance(h, handlers.TimedRotatingFileHandler) for h in root.handlers):
        root.addHandler(file_handler)

    root.setLevel(logging.INFO)

    # Configure structlog for async callers (main.py)
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.contextvars.merge_contextvars,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.ExceptionPrettyPrinter(),
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.AsyncBoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    config = structlog.get_config()
    return structlog.stdlib.BoundLogger(
        logging.getLogger(logger_name),
        config["processors"],
        config["context_class"](),
    )


__all__ = [
    "StructuredLogFormatter",
    "set_correlation_id",
    "reset_correlation_id",
    "get_correlation_id",
    "initialize_logger",
]
