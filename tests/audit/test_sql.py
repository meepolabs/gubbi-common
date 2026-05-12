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
from gubbi_common.audit.targets import TargetKind

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
# (gubbi Alembic migration 0012), NOT emitted from gubbi_common/audit/sql.py.
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
        target_id="00000000-0000-0000-0000-0000000000ab",
        target_kind=TargetKind.USER,
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
    assert args[4] == "00000000-0000-0000-0000-0000000000ab"
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
            actor_id="system:worker",
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
            actor_id="system:worker",
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
        actor_id="00000000-0000-0000-0000-000000000001",
        action="login_failed",
        ip_address="192.0.2.1",
    )
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="00000000-0000-0000-0000-000000000001",
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
        actor_id="system:worker",
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
        actor_id="00000000-0000-0000-0000-000000000001",
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
        actor_id="00000000-0000-0000-0000-000000000001",
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
            actor_id="00000000-0000-0000-0000-000000000001",
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
            actor_id="00000000-0000-0000-0000-000000000001",
            action="login_failed",
            ip_address="not-an-ip",
        )
    cause = excinfo.value.__cause__
    assert cause is not None, "ValueError must chain the original cause via 'from exc'"
    assert isinstance(cause, ValueError)


# ---------------------------------------------------------------------------
# H-17.2: metadata size cap + banned-key redaction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_metadata_size_cap_constant_exposed() -> None:
    from gubbi_common.audit.sql import MAX_METADATA_BYTES

    assert MAX_METADATA_BYTES == 4096


@pytest.mark.asyncio
@pytest.mark.unit
async def test_metadata_under_cap_persisted_as_is() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        metadata={"k": "v", "count": 7},
    )
    _, *args = conn.calls[0]
    payload = args[6]
    import json as _json

    assert _json.loads(payload) == {"k": "v", "count": 7}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_metadata_over_cap_raises_value_error() -> None:
    """A metadata payload over 4096 JSON-encoded bytes is rejected."""
    conn = _StubConn()
    huge = {"blob": "x" * 4100}
    with pytest.raises(ValueError, match="metadata exceeds"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:worker",
            action="identity.created",
            metadata=huge,
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_metadata_banned_key_redacted() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        metadata={"password": "hunter2", "ok": "value"},
    )
    _, *args = conn.calls[0]
    import json as _json

    persisted = _json.loads(args[6])
    assert persisted["password"] == "[REDACTED]"
    assert persisted["ok"] == "value"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_metadata_banned_key_recursive_redaction() -> None:
    conn = _StubConn()
    nested = {
        "outer": {
            "password": "hunter2",
            "list": [{"email": "a@b"}, {"safe": 1}],
        }
    }
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        metadata=nested,
    )
    _, *args = conn.calls[0]
    import json as _json

    persisted = _json.loads(args[6])
    assert persisted["outer"]["password"] == "[REDACTED]"
    assert persisted["outer"]["list"][0]["email"] == "[REDACTED]"
    assert persisted["outer"]["list"][1]["safe"] == 1


@pytest.mark.asyncio
@pytest.mark.unit
async def test_metadata_derivative_suffix_not_redacted() -> None:
    """``password_hash`` IS redacted because ``password`` is a NEVER_EXEMPT_BASE.

    The plan's spec name is misleading -- ``password_hash`` is still banned
    via NEVER_EXEMPT_BASES even though it carries a derivative suffix. A
    derivative-only banned key (e.g. ``email_hash``) IS exempt.
    """
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        metadata={"password_hash": "abc", "email_hash": "def"},
    )
    _, *args = conn.calls[0]
    import json as _json

    persisted = _json.loads(args[6])
    assert persisted["password_hash"] == "[REDACTED]"
    assert persisted["email_hash"] == "def"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_metadata_oversize_after_redaction_still_rejects() -> None:
    """Cap is enforced after redaction; a large redacted payload still fails."""
    conn = _StubConn()
    # Use non-banned keys so redaction does not collapse the payload.
    payload = {f"item_{i}": "y" * 100 for i in range(50)}
    with pytest.raises(ValueError, match="metadata exceeds"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:worker",
            action="identity.created",
            metadata=payload,
        )
    assert conn.calls == []


# ---------------------------------------------------------------------------
# A-H6: redaction recursion depth cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_metadata_deeply_nested_raises_value_error() -> None:
    """A 25-deep nested dict trips the _MAX_REDACT_DEPTH=20 cap.

    The cap protects the redactor from pathological client input that
    would otherwise blow the Python recursion limit and crash the worker.
    """
    conn = _StubConn()
    # Build a 25-deep nested dict.
    deep: dict[str, Any] = {"v": 1}
    for _ in range(25):
        deep = {"k": deep}
    with pytest.raises(ValueError, match="redaction depth"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:worker",
            action="identity.created",
            metadata=deep,
        )
    assert conn.calls == []


@pytest.mark.unit
def test_redact_metadata_depth_cap_constant() -> None:
    from gubbi_common.audit.sql import _MAX_REDACT_DEPTH

    assert _MAX_REDACT_DEPTH == 20


@pytest.mark.unit
def test_redact_metadata_shallow_passes() -> None:
    """A reasonably shallow nested dict redacts without raising.

    Depth accounting increments on every recurse across both helpers,
    so a dict-only chain advances depth by 2 per visible level. A
    9-deep dict-only chain stays well under the 20 cap.
    """
    from gubbi_common.audit.sql import _redact_metadata

    deep: dict[str, Any] = {"v": 1}
    for _ in range(9):
        deep = {"k": deep}
    out = _redact_metadata(deep)
    assert isinstance(out, dict)


# ---------------------------------------------------------------------------
# A-M2: tuple recursion in redaction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_redact_metadata_recurses_into_tuple() -> None:
    """Tuples are walked element-wise, same as lists.

    json.dumps already collapses tuples to JSON arrays, so the redactor
    matching that behaviour is the only honest contract. The output is
    a list so downstream typing stays JSON-shaped.
    """
    from gubbi_common.audit.sql import _redact_metadata

    meta = {"items": ({"password": "x"}, {"safe": 1})}
    out = _redact_metadata(meta)
    items = out["items"]
    # Output is a list (tuple collapsed); element-wise redaction applied.
    assert isinstance(items, list)
    assert items[0] == {"password": "[REDACTED]"}
    assert items[1] == {"safe": 1}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_tuple_metadata_redacted() -> None:
    """End-to-end: a tuple inside metadata is JSON-serialised after redaction."""
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        metadata={"items": ({"email": "a@b"}, {"ok": "v"})},
    )
    _, *args = conn.calls[0]
    import json as _json

    persisted = _json.loads(args[6])
    assert persisted["items"][0]["email"] == "[REDACTED]"
    assert persisted["items"][1]["ok"] == "v"


# ---------------------------------------------------------------------------
# H-17.3: actor_id / target_id shape validation (UUID or known prefix)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_actor_id_uuid_accepted() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="00000000-0000-0000-0000-000000000001",
        action="login_failed",
    )
    assert len(conn.calls) == 1


@pytest.mark.asyncio
@pytest.mark.unit
async def test_actor_id_system_prefix_accepted() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:extraction-worker",
        action="conversation.extracted",
    )
    assert len(conn.calls) == 1


@pytest.mark.asyncio
@pytest.mark.unit
async def test_actor_id_script_prefix_accepted() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="script:rotate_encryption_key",
        action="encryption.key_rotated",
    )
    assert len(conn.calls) == 1


@pytest.mark.asyncio
@pytest.mark.unit
async def test_actor_id_hydra_subject_prefix_accepted() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="hydra_subject",
        actor_id="hydra_subject:abc123",
        action="login_failed",
    )
    assert len(conn.calls) == 1


@pytest.mark.asyncio
@pytest.mark.unit
async def test_actor_id_empty_string_rejected() -> None:
    conn = _StubConn()
    with pytest.raises(ValueError, match="actor_id"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="user",
            actor_id="",
            action="login_failed",
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_actor_id_unknown_prefix_rejected() -> None:
    conn = _StubConn()
    with pytest.raises(ValueError, match="actor_id"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="user",
            actor_id="x",
            action="login_failed",
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_target_id_none_accepted() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        target_id=None,
    )
    assert len(conn.calls) == 1


@pytest.mark.asyncio
@pytest.mark.unit
async def test_target_id_uuid_accepted() -> None:
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        target_id="11111111-2222-3333-4444-555555555555",
        target_kind=TargetKind.USER,
    )
    assert len(conn.calls) == 1


@pytest.mark.asyncio
@pytest.mark.unit
async def test_target_id_unknown_rejected() -> None:
    conn = _StubConn()
    with pytest.raises(ValueError, match="target_id"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:worker",
            action="identity.created",
            target_id="not-a-uuid-or-prefix",
            target_kind=TargetKind.USER,
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_target_id_without_target_kind_rejected() -> None:
    """Direct test for the ``target_id requires target_kind`` invariant.

    The invariant added alongside migration 0020 fires when a caller
    supplies ``target_id`` without ``target_kind``. Without this test,
    a regression that drops the guard would only surface at the DB
    layer (NULL target_kind on a row that should carry it for dedup).
    """
    conn = _StubConn()
    with pytest.raises(ValueError, match="target_id requires target_kind"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:worker",
            action="identity.created",
            target_id="some-id",
            # target_kind deliberately omitted
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_accepts_action_enum_member() -> None:
    """Action members are StrEnum -- pass them directly to ``action=``."""
    from gubbi_common.audit.actions import Action

    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="00000000-0000-0000-0000-000000000001",
        action=Action.LOGIN_FAILED,
    )
    _, *args = conn.calls[0]
    assert args[2] == "login_failed"
