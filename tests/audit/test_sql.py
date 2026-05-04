"""Tests for shared ``audit_log`` SQL constants and the typed wrapper."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from gubbi_common.audit.sql import (
    AUDIT_INSERT_DEDUPED_SQL,
    AUDIT_INSERT_SHORT_SQL,
    AUDIT_INSERT_SQL,
    AUDIT_INSERT_SQL_RICH,
    VALID_ACTOR_TYPES,
    record_audit_async,
)

# ---------------------------------------------------------------------------
# SQL string shape
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_canonical_insert_targets_audit_log() -> None:
    assert "INSERT INTO audit_log" in AUDIT_INSERT_SQL


@pytest.mark.unit
def test_canonical_insert_has_nine_placeholders() -> None:
    # Arrange
    placeholders = [f"${n}" for n in range(1, 10)]

    # Act / Assert: every $1..$9 referenced exactly once.
    for ph in placeholders:
        assert ph in AUDIT_INSERT_SQL, f"missing placeholder {ph}"
    assert "$10" not in AUDIT_INSERT_SQL


@pytest.mark.unit
def test_canonical_insert_casts_metadata_and_ip() -> None:
    assert "::jsonb" in AUDIT_INSERT_SQL
    assert "::inet" in AUDIT_INSERT_SQL


@pytest.mark.unit
def test_short_insert_has_six_placeholders_and_metadata_cast() -> None:
    for ph in ("$1", "$2", "$3", "$4", "$5", "$6"):
        assert ph in AUDIT_INSERT_SHORT_SQL
    assert "$7" not in AUDIT_INSERT_SHORT_SQL
    assert "::jsonb" in AUDIT_INSERT_SHORT_SQL


@pytest.mark.unit
def test_deduped_insert_has_on_conflict_do_nothing() -> None:
    assert "ON CONFLICT" in AUDIT_INSERT_DEDUPED_SQL
    assert "DO NOTHING" in AUDIT_INSERT_DEDUPED_SQL
    assert "content_hash" in AUDIT_INSERT_DEDUPED_SQL
    assert "RETURNING 1" in AUDIT_INSERT_DEDUPED_SQL


@pytest.mark.unit
def test_rich_insert_has_seven_placeholders_and_occurred_at() -> None:
    for ph in ("$1", "$2", "$3", "$4", "$5", "$6", "$7"):
        assert ph in AUDIT_INSERT_SQL_RICH
    assert "$8" not in AUDIT_INSERT_SQL_RICH
    assert "occurred_at" in AUDIT_INSERT_SQL_RICH


# ---------------------------------------------------------------------------
# VALID_ACTOR_TYPES
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_valid_actor_types_set() -> None:
    assert frozenset({"user", "admin", "system", "hydra_subject"}) == VALID_ACTOR_TYPES


# TODO(m234-low): VALID_ACTOR_TYPES <-> DB CHECK constraint sync test.
# The audit_log.actor_type CHECK constraint is defined in consumer migrations
# (journalctl Alembic migration 0012), NOT emitted from gubbi_common/audit/sql.py.
# Until the library either:
#   1.) emits the DDL string, or
#   2.) provides a helper that reads the constraint from the running schema,
# there is no reliable way to parse it at test time.  The best we can do
# today is maintain a comment in each consumer migration pointing here and
# an assertion on the Python values (above).  Revisit when gubbi-common owns
# a source of truth for the CHECK constraint definition.


# ---------------------------------------------------------------------------
# record_audit_async signature + behaviour (using a stub asyncpg conn)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_record_audit_async_signature_is_kw_only_after_conn() -> None:
    # Arrange
    sig = inspect.signature(record_audit_async)
    params = list(sig.parameters.values())

    # Act / Assert: first param positional (conn), rest keyword-only.
    assert params[0].name == "conn"
    assert params[0].kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.POSITIONAL_ONLY,
    )
    for p in params[1:]:
        assert p.kind == inspect.Parameter.KEYWORD_ONLY, f"param {p.name!r} should be keyword-only"


class _StubConn:
    """Minimal asyncpg.Connection stand-in capturing execute() calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    async def execute(self, sql: str, *args: Any) -> None:
        self.calls.append((sql, *args))


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_executes_canonical_insert() -> None:
    # Arrange
    conn = _StubConn()

    # Act
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        target_type="user",
        target_id="abc",
        metadata={"k": "v"},
    )

    # Assert
    assert len(conn.calls) == 1
    sql, *args = conn.calls[0]
    assert sql == AUDIT_INSERT_SQL
    assert args[0] == "system"
    assert args[1] == "system:worker"
    assert args[2] == "identity.created"
    assert args[3] == "user"
    assert args[4] == "abc"
    # metadata is JSON-encoded
    assert args[6] == '{"k": "v"}'


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_rejects_invalid_actor_type() -> None:
    conn = _StubConn()
    with pytest.raises(ValueError, match="Invalid actor_type"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="root",
            actor_id="x",
            action="identity.created",
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_rejects_malformed_ip() -> None:
    conn = _StubConn()
    with pytest.raises(ValueError, match="invalid ip_address"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="x",
            action="login_failed",
            ip_address="not-an-ip",
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_accepts_ipv4_and_ipv6() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="x",
        action="login_failed",
        ip_address="192.0.2.1",
    )
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="x",
        action="login_failed",
        ip_address="2001:db8::1",
    )
    assert len(conn.calls) == 2


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_defaults_metadata_to_empty_dict() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="x",
        action="identity.created",
    )
    _, *args = conn.calls[0]
    assert args[6] == "{}"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_normalizes_ipv6_zero_compression() -> None:
    """IPv6 with explicit zero blocks is collapsed to canonical form."""
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="x",
        action="login_failed",
        ip_address="2001:0db8:0000:0000:0000:0000:0000:0001",
    )
    _, *args = conn.calls[0]
    # ip_address is positional arg index 7 (0-based) per the canonical INSERT
    assert args[7] == "2001:db8::1"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_normalizes_ipv4_mapped_ipv6() -> None:
    """IPv4-mapped IPv6 collapses to bare IPv4 so dedup works across reps."""
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="x",
        action="login_failed",
        ip_address="::ffff:127.0.0.1",
    )
    _, *args = conn.calls[0]
    assert args[7] == "127.0.0.1"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_rejects_scoped_ipv6() -> None:
    """Scoped IPv6 (fe80::1%eth0) is rejected -- zone IDs are originator-local
    and may carry control chars that poison log pipelines."""
    conn = _StubConn()
    with pytest.raises(ValueError, match="scoped IPv6"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="user",
            actor_id="x",
            action="login_failed",
            ip_address="fe80::1%eth0",
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_invalid_ip_chains_cause() -> None:
    """ValueError raised on bad IP must preserve the original exception via __cause__."""
    conn = _StubConn()
    with pytest.raises(ValueError, match="invalid ip_address") as excinfo:
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="user",
            actor_id="x",
            action="login_failed",
            ip_address="not-an-ip",
        )
    cause = excinfo.value.__cause__
    assert cause is not None, "ValueError must chain the original cause via 'from exc'"
    assert isinstance(cause, ValueError)
