"""Audit-writer failure telemetry must carry no driver-supplied text.

Both writers emit an ``audit.write`` span. When the INSERT fails, the
span must describe the failure with the exception class name and an
optional validated SQLSTATE only -- never the driver message, the
database DETAIL/HINT text, or a stack trace, any of which can embed a
session id, an IP, a user agent, or a token-shaped value.

The suite captures real SDK spans through an in-memory exporter, so an
assertion here fails if a value actually reaches the exporter -- not
merely if a call site looks wrong. A positive control in the same file
records the same exception the old way and proves the harness surfaces
every planted marker, so the negative assertions cannot pass vacuously.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Literal

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from gubbi_common.audit.sql import (
    AUDIT_WRITE_FAILED_EVENT_NAME,
    AUDIT_WRITE_SPAN_NAME,
    record_audit_async,
    record_audit_deduped_async,
)
from gubbi_common.audit.targets import TargetKind

if TYPE_CHECKING:
    from collections.abc import Awaitable

# The two writer paths, as a closed set. Parametrized cases and the
# dispatch helper share the alias so a misspelled case name is a typing
# error rather than a silent fall-through to the dedup writer.
_Writer = Literal["canonical", "deduped"]
_WRITERS: tuple[_Writer, ...] = ("canonical", "deduped")

# Synthetic values planted in the failing driver exception's message.
# Each stands in for one class of value that must never reach telemetry:
# an opaque session id, an originating IP (documentation range), a user
# agent, and a token-shaped credential.
_MARKER_SID = "sid-zzzzplantedsession"
_MARKER_IP = "203.0.113.77"
_MARKER_UA = "PlantedAgent/9.9 (marker-user-agent)"
_MARKER_TOKEN = "plantedtokenvalue-zzzz"
_MARKER_DETAIL = "DETAIL: planted database detail text"

_ALL_MARKERS = (
    _MARKER_SID,
    _MARKER_IP,
    _MARKER_UA,
    _MARKER_TOKEN,
    _MARKER_DETAIL,
)

_ACTOR_ID = "00000000-0000-0000-0000-00000000beef"


class _PlantedDriverError(Exception):
    """Stand-in for an asyncpg error whose message carries planted markers."""

    def __init__(self, sqlstate: Any = None) -> None:
        super().__init__(
            f"insufficient privilege for relation audit_log "
            f"[sid={_MARKER_SID} ip={_MARKER_IP} ua={_MARKER_UA} "
            f"token={_MARKER_TOKEN}] {_MARKER_DETAIL}"
        )
        if sqlstate is not None:
            self.sqlstate = sqlstate


class _PlantedCancelledError(asyncio.CancelledError):
    """A cancellation whose message carries the same planted markers.

    ``asyncio.CancelledError`` derives from ``BaseException`` in Python
    3.8+, so a failure block that catches only ``Exception`` lets the
    SDK's own handler see it. Cancellation messages are caller-supplied
    and a cancelled audit write is cancelled mid-statement, so the same
    driver/database text can ride along.
    """

    def __init__(self, sqlstate: Any = None) -> None:
        super().__init__(
            f"cancelled while inserting into audit_log "
            f"[sid={_MARKER_SID} ip={_MARKER_IP} ua={_MARKER_UA} "
            f"token={_MARKER_TOKEN}] {_MARKER_DETAIL}"
        )
        if sqlstate is not None:
            self.sqlstate = sqlstate


class _FailingExecuteConn:
    """Connection stub whose canonical INSERT always raises."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def execute(self, sql: str, *args: Any) -> None:
        raise self._exc


class _FailingFetchvalConn:
    """Connection stub whose dedup INSERT always raises."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def fetchval(self, sql: str, *args: Any) -> int | None:
        raise self._exc


@pytest.fixture
def exporter(monkeypatch: pytest.MonkeyPatch) -> InMemorySpanExporter:
    """Route audit spans into an in-memory exporter for this test."""
    span_exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    monkeypatch.setattr(trace, "get_tracer", lambda name, *a, **kw: provider.get_tracer(name))
    return span_exporter


def _only_span(exporter: InMemorySpanExporter) -> ReadableSpan:
    spans = exporter.get_finished_spans()
    assert len(spans) == 1, f"expected exactly one exported span, got {len(spans)}"
    return spans[0]


def _span_text(span: ReadableSpan) -> str:
    """Flatten every exporter-visible string on *span* into one blob."""
    parts: list[str] = [span.name]
    for key, value in (span.attributes or {}).items():
        parts.append(str(key))
        parts.append(str(value))
    if span.status is not None and span.status.description is not None:
        parts.append(span.status.description)
    for event in span.events:
        parts.append(event.name)
        for key, value in (event.attributes or {}).items():
            parts.append(str(key))
            parts.append(str(value))
    return "\n".join(parts)


def _failure_event(span: ReadableSpan) -> Any:
    matches = [event for event in span.events if event.name == AUDIT_WRITE_FAILED_EVENT_NAME]
    assert len(matches) == 1, (
        f"expected exactly one failure event, saw {[e.name for e in span.events]}"
    )
    return matches[0]


async def _write_canonical(conn: Any) -> None:
    await record_audit_async(
        conn,
        actor_type="user",
        actor_id=_ACTOR_ID,
        action="session.revoked",
        target_type="session",
        target_id="session-handle",
        target_kind=TargetKind.SESSION,
    )


async def _write_deduped(conn: Any) -> None:
    await record_audit_deduped_async(
        conn,
        actor_type="user",
        actor_id=_ACTOR_ID,
        action="session.revoked",
        target_kind=TargetKind.SESSION,
        target_type="session",
        target_id="session-handle",
        metadata={"content_hash": "deadbeef"},
    )


# ---------------------------------------------------------------------------
# Positive control: the harness does surface planted markers
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_harness_surfaces_planted_markers_when_exception_is_recorded_raw(
    exporter: InMemorySpanExporter,
) -> None:
    """Control: ``record_exception`` puts every planted marker on the span."""
    # Arrange
    tracer = trace.get_tracer("gubbi_common.audit")

    # Act
    with tracer.start_as_current_span(AUDIT_WRITE_SPAN_NAME) as span:
        span.record_exception(_PlantedDriverError(sqlstate="42501"))

    # Assert
    blob = _span_text(_only_span(exporter))
    for marker in _ALL_MARKERS:
        assert marker in blob, f"harness failed to capture planted marker {marker!r}"


# ---------------------------------------------------------------------------
# Neither writer leaks driver text on failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_canonical_writer_failure_span_carries_no_driver_text(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    conn = _FailingExecuteConn(_PlantedDriverError(sqlstate="42501"))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_canonical(conn)

    # Assert
    blob = _span_text(_only_span(exporter))
    for marker in _ALL_MARKERS:
        assert marker not in blob, f"planted marker {marker!r} reached span telemetry"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_deduped_writer_failure_span_carries_no_driver_text(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    conn = _FailingFetchvalConn(_PlantedDriverError(sqlstate="42501"))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_deduped(conn)

    # Assert
    blob = _span_text(_only_span(exporter))
    for marker in _ALL_MARKERS:
        assert marker not in blob, f"planted marker {marker!r} reached span telemetry"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_canonical_writer_failure_records_no_exception_event(
    exporter: InMemorySpanExporter,
) -> None:
    """No OTel ``exception`` event, so no message/stacktrace attributes exist."""
    # Arrange
    conn = _FailingExecuteConn(_PlantedDriverError(sqlstate="42501"))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_canonical(conn)

    # Assert
    span = _only_span(exporter)
    assert [event.name for event in span.events if event.name == "exception"] == []
    for event in span.events:
        assert "exception.message" not in (event.attributes or {})
        assert "exception.stacktrace" not in (event.attributes or {})


@pytest.mark.asyncio
@pytest.mark.unit
async def test_deduped_writer_failure_records_no_exception_event(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    conn = _FailingFetchvalConn(_PlantedDriverError(sqlstate="42501"))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_deduped(conn)

    # Assert
    span = _only_span(exporter)
    assert [event.name for event in span.events if event.name == "exception"] == []
    for event in span.events:
        assert "exception.message" not in (event.attributes or {})
        assert "exception.stacktrace" not in (event.attributes or {})


# ---------------------------------------------------------------------------
# Sanitized event shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_canonical_writer_failure_event_carries_type_and_sqlstate_only(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    conn = _FailingExecuteConn(_PlantedDriverError(sqlstate="42501"))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_canonical(conn)

    # Assert
    event = _failure_event(_only_span(exporter))
    assert dict(event.attributes) == {
        "exception.type": "_PlantedDriverError",
        "db.sqlstate": "42501",
    }


@pytest.mark.asyncio
@pytest.mark.unit
async def test_deduped_writer_failure_event_carries_type_and_sqlstate_only(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    conn = _FailingFetchvalConn(_PlantedDriverError(sqlstate="42501"))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_deduped(conn)

    # Assert
    event = _failure_event(_only_span(exporter))
    assert dict(event.attributes) == {
        "exception.type": "_PlantedDriverError",
        "db.sqlstate": "42501",
    }


@pytest.mark.asyncio
@pytest.mark.unit
async def test_failure_event_omits_sqlstate_when_exception_carries_none(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange: a driver-agnostic failure with no sqlstate attribute at all.
    conn = _FailingExecuteConn(_PlantedDriverError())

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_canonical(conn)

    # Assert
    event = _failure_event(_only_span(exporter))
    assert dict(event.attributes) == {"exception.type": "_PlantedDriverError"}


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.parametrize(
    "sqlstate",
    [
        pytest.param("4250", id="too-short"),
        pytest.param("425011", id="too-long"),
        pytest.param("", id="empty"),
        pytest.param("425 1", id="space"),
        pytest.param(f"4250{_MARKER_SID}", id="marker-suffixed"),
        pytest.param(42501, id="non-string"),
        pytest.param(None, id="explicit-none"),
        pytest.param("425o1", id="lowercase-letter"),
    ],
)
async def test_failure_event_omits_sqlstate_when_value_fails_validation(
    exporter: InMemorySpanExporter,
    sqlstate: Any,
) -> None:
    # Arrange
    exc = _PlantedDriverError()
    exc.sqlstate = sqlstate  # type: ignore[attr-defined]
    conn = _FailingFetchvalConn(exc)

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_deduped(conn)

    # Assert
    event = _failure_event(_only_span(exporter))
    assert dict(event.attributes) == {"exception.type": "_PlantedDriverError"}


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.parametrize("sqlstate", ["23505", "42501", "0A000", "P0001"])
async def test_failure_event_keeps_five_character_sqlstate(
    exporter: InMemorySpanExporter,
    sqlstate: str,
) -> None:
    """A five-character uppercase-alphanumeric SQLSTATE is kept verbatim."""
    # Arrange
    conn = _FailingFetchvalConn(_PlantedDriverError(sqlstate=sqlstate))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_deduped(conn)

    # Assert
    event = _failure_event(_only_span(exporter))
    assert event.attributes["db.sqlstate"] == sqlstate


# ---------------------------------------------------------------------------
# Error status without description
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_canonical_writer_failure_sets_error_status_without_description(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    conn = _FailingExecuteConn(_PlantedDriverError(sqlstate="42501"))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_canonical(conn)

    # Assert
    status = _only_span(exporter).status
    assert status.status_code is StatusCode.ERROR
    assert status.description is None


@pytest.mark.asyncio
@pytest.mark.unit
async def test_deduped_writer_failure_sets_error_status_without_description(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    conn = _FailingFetchvalConn(_PlantedDriverError(sqlstate="42501"))

    # Act
    with pytest.raises(_PlantedDriverError):
        await _write_deduped(conn)

    # Assert
    status = _only_span(exporter).status
    assert status.status_code is StatusCode.ERROR
    assert status.description is None


# ---------------------------------------------------------------------------
# Success path unchanged
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_successful_write_emits_allowlisted_attributes_and_no_failure_event(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    class _OkConn:
        async def execute(self, sql: str, *args: Any) -> None:
            return None

    # Act
    await _write_canonical(_OkConn())

    # Assert
    span = _only_span(exporter)
    assert span.events == ()
    assert span.status.status_code is not StatusCode.ERROR
    attrs = dict(span.attributes or {})
    assert attrs["event_type"] == "session.revoked"
    assert attrs["actor_type"] == "user"
    assert attrs["success"] is True
    assert "latency_ms" in attrs


# ---------------------------------------------------------------------------
# Pre-SQL validation failures never open a span at all
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_rejected_ip_on_canonical_path_emits_no_span(
    exporter: InMemorySpanExporter,
) -> None:
    """A rejected ``ip_address`` raises before any span opens.

    The raised message echoes the rejected value, which is why the
    rejection must stay outside the span: no span exists to carry it.
    """

    # Arrange
    class _UnusedConn:
        async def execute(self, sql: str, *args: Any) -> None:
            raise AssertionError("INSERT must not run when ip_address is rejected")

    # Act
    with pytest.raises(ValueError, match="invalid ip_address") as excinfo:
        await record_audit_async(
            _UnusedConn(),
            actor_type="user",
            actor_id=_ACTOR_ID,
            action="session.revoked",
            ip_address=f"{_MARKER_IP}-not-an-ip",
        )

    # Assert
    assert _MARKER_IP in str(excinfo.value)
    assert exporter.get_finished_spans() == ()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_rejected_ip_on_deduped_path_emits_no_span(
    exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    class _UnusedConn:
        async def fetchval(self, sql: str, *args: Any) -> int | None:
            raise AssertionError("INSERT must not run when ip_address is rejected")

    # Act
    with pytest.raises(ValueError, match="invalid ip_address"):
        await record_audit_deduped_async(
            _UnusedConn(),
            actor_type="user",
            actor_id=_ACTOR_ID,
            action="session.revoked",
            target_kind=TargetKind.SESSION,
            metadata={"content_hash": "deadbeef"},
            ip_address=f"{_MARKER_IP}-not-an-ip",
        )

    # Assert
    assert exporter.get_finished_spans() == ()


# ---------------------------------------------------------------------------
# Cancellation is sanitized too
# ---------------------------------------------------------------------------
#
# ``asyncio.CancelledError`` is a ``BaseException``. The OTel SDK's own
# ``use_span`` handler catches only ``Exception``, so a failure block that
# does the same leaves a cancelled audit write with no failure event and
# no error status at all -- the cancellation message, which is
# caller-supplied and raised mid-statement, is never sanitized because it
# is never handled.


def _cancellation_writer(writer: _Writer, exc: BaseException) -> Awaitable[None]:
    """Return the awaitable that drives *writer* against a cancelling conn."""
    if writer == "canonical":
        return _write_canonical(_FailingExecuteConn(exc))
    return _write_deduped(_FailingFetchvalConn(exc))


@pytest.mark.unit
def test_harness_surfaces_planted_markers_when_cancellation_is_recorded_raw(
    exporter: InMemorySpanExporter,
) -> None:
    """Control: the cancellation message is marker-bearing and capturable."""
    # Arrange
    tracer = trace.get_tracer("gubbi_common.audit")

    # Act
    with tracer.start_as_current_span(AUDIT_WRITE_SPAN_NAME) as span:
        span.record_exception(_PlantedCancelledError(sqlstate="57014"))

    # Assert
    blob = _span_text(_only_span(exporter))
    for marker in _ALL_MARKERS:
        assert marker in blob, f"harness failed to capture planted marker {marker!r}"


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.parametrize("writer", _WRITERS)
async def test_cancellation_propagates_from_both_writers(
    exporter: InMemorySpanExporter,
    writer: _Writer,
) -> None:
    # Arrange / Act / Assert
    with pytest.raises(asyncio.CancelledError):
        await _cancellation_writer(writer, _PlantedCancelledError())


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.parametrize("writer", _WRITERS)
async def test_cancellation_emits_one_sanitized_failure_event_without_sqlstate(
    exporter: InMemorySpanExporter,
    writer: _Writer,
) -> None:
    # Arrange / Act
    with pytest.raises(asyncio.CancelledError):
        await _cancellation_writer(writer, _PlantedCancelledError())

    # Assert
    event = _failure_event(_only_span(exporter))
    assert dict(event.attributes) == {"exception.type": "_PlantedCancelledError"}


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.parametrize("writer", _WRITERS)
async def test_cancellation_keeps_sqlstate_when_the_cancellation_carries_one(
    exporter: InMemorySpanExporter,
    writer: _Writer,
) -> None:
    """A driver that cancels a statement supplies SQLSTATE 57014."""
    # Arrange / Act
    with pytest.raises(asyncio.CancelledError):
        await _cancellation_writer(writer, _PlantedCancelledError(sqlstate="57014"))

    # Assert
    event = _failure_event(_only_span(exporter))
    assert dict(event.attributes) == {
        "exception.type": "_PlantedCancelledError",
        "db.sqlstate": "57014",
    }


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.parametrize("writer", _WRITERS)
async def test_cancellation_sets_error_status_without_description(
    exporter: InMemorySpanExporter,
    writer: _Writer,
) -> None:
    # Arrange / Act
    with pytest.raises(asyncio.CancelledError):
        await _cancellation_writer(writer, _PlantedCancelledError())

    # Assert
    status = _only_span(exporter).status
    assert status.status_code is StatusCode.ERROR
    assert status.description is None


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.parametrize("writer", _WRITERS)
async def test_cancellation_span_carries_no_raw_message_or_stacktrace(
    exporter: InMemorySpanExporter,
    writer: _Writer,
) -> None:
    # Arrange / Act
    with pytest.raises(asyncio.CancelledError):
        await _cancellation_writer(writer, _PlantedCancelledError(sqlstate="57014"))

    # Assert
    span = _only_span(exporter)
    blob = _span_text(span)
    for marker in _ALL_MARKERS:
        assert marker not in blob, f"planted marker {marker!r} reached span telemetry"
    assert [event.name for event in span.events if event.name == "exception"] == []
    for event in span.events:
        assert "exception.message" not in (event.attributes or {})
        assert "exception.stacktrace" not in (event.attributes or {})


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.parametrize("writer", _WRITERS)
async def test_bare_cancelled_error_is_sanitized_under_its_own_class_name(
    exporter: InMemorySpanExporter,
    writer: _Writer,
) -> None:
    """The stdlib cancellation, not only the marker-bearing subclass."""
    # Arrange / Act
    with pytest.raises(asyncio.CancelledError):
        await _cancellation_writer(writer, asyncio.CancelledError())

    # Assert
    event = _failure_event(_only_span(exporter))
    assert dict(event.attributes) == {"exception.type": "CancelledError"}


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_failure_event_name_is_importable_from_the_audit_package() -> None:
    """Consumers build backend queries on the name, so it is package-public."""
    # Arrange / Act
    import gubbi_common.audit as audit_pkg

    # Assert
    assert audit_pkg.AUDIT_WRITE_FAILED_EVENT_NAME == AUDIT_WRITE_FAILED_EVENT_NAME
    assert "AUDIT_WRITE_FAILED_EVENT_NAME" in audit_pkg.__all__
