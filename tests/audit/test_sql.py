"""Tests for shared ``audit_log`` SQL constants and the typed wrappers."""

from __future__ import annotations

import inspect
import json
from typing import Any

import pytest

from gubbi_common.audit.sql import (
    AUDIT_INSERT_DEDUPED_SQL,
    AUDIT_INSERT_SQL,
    VALID_ACTOR_TYPES,
    record_audit_async,
    record_audit_deduped_async,
)
from gubbi_common.audit.targets import TargetKind

# ---------------------------------------------------------------------------
# SQL string shape
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_canonical_insert_targets_audit_log() -> None:
    assert "INSERT INTO audit_log" in AUDIT_INSERT_SQL


@pytest.mark.unit
def test_canonical_insert_has_ten_placeholders() -> None:
    # Arrange
    placeholders = [f"${n}" for n in range(1, 11)]

    # Act / Assert: every $1..$10 referenced exactly once.
    for ph in placeholders:
        assert ph in AUDIT_INSERT_SQL, f"missing placeholder {ph}"
    assert "$11" not in AUDIT_INSERT_SQL


@pytest.mark.unit
def test_canonical_insert_includes_target_kind_column() -> None:
    assert "target_kind" in AUDIT_INSERT_SQL


@pytest.mark.unit
def test_canonical_insert_casts_metadata_and_ip() -> None:
    assert "::jsonb" in AUDIT_INSERT_SQL
    assert "::inet" in AUDIT_INSERT_SQL


@pytest.mark.unit
def test_deduped_insert_has_on_conflict_do_nothing() -> None:
    assert "ON CONFLICT" in AUDIT_INSERT_DEDUPED_SQL
    assert "DO NOTHING" in AUDIT_INSERT_DEDUPED_SQL
    assert "content_hash" in AUDIT_INSERT_DEDUPED_SQL
    assert "RETURNING 1" in AUDIT_INSERT_DEDUPED_SQL


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
    assert args[5] == TargetKind.USER
    # metadata is JSON-encoded at index 7 (after target_kind + reason)
    assert args[7] == '{"k": "v"}'


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
    assert args[7] == "{}"


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
    # ip_address is positional arg index 8 (0-based) per the canonical 10-column INSERT
    assert args[8] == "2001:db8::1"


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
    assert args[8] == "127.0.0.1"


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


@pytest.mark.unit
def test_normalize_ip_whitespace_returns_none() -> None:
    """A whitespace-only ip_address is treated as "no IP".

    Regression: pre-strip code did ``if not ip_address: return None``,
    which is truthy for ``"   "``. The fall-through called
    ``ipaddress.ip_address("   ")`` which raises ``ValueError`` and
    surfaced as "invalid ip_address" to the caller. Treating
    whitespace-only as None keeps the optional-caller contract intact.
    """
    from gubbi_common.audit.sql import _normalize_ip

    assert _normalize_ip("   ") is None
    assert _normalize_ip("\t") is None
    assert _normalize_ip("\n") is None
    assert _normalize_ip(None) is None
    assert _normalize_ip("") is None
    # Non-whitespace input still parses (sanity check on the strip ordering).
    assert _normalize_ip("  192.0.2.1  ") == "192.0.2.1"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_whitespace_ip_treated_as_none() -> None:
    """End-to-end: whitespace-only ip_address surfaces as NULL on the row."""
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="00000000-0000-0000-0000-000000000001",
        action="login_failed",
        ip_address="   ",
    )
    _, *args = conn.calls[0]
    # ip_address slot is positional arg index 8 (0-based) on the 10-column INSERT.
    assert args[8] is None


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
    payload = args[7]
    assert json.loads(payload) == {"k": "v", "count": 7}


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
    persisted = json.loads(args[7])
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
    persisted = json.loads(args[7])
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
    persisted = json.loads(args[7])
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
    persisted = json.loads(args[7])
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
async def test_target_id_arbitrary_string_accepted() -> None:
    """target_id passes through verbatim -- conversation integers,
    Stripe sub_xxx, SHA256 email hashes all coexist in the column.

    The shape-validation is only applied to actor_id (S2 LOW-1).
    """
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        target_id="sub_1NV3Df",  # external Stripe ID, not UUID
        target_kind=TargetKind.SUBSCRIPTION,
    )
    assert len(conn.calls) == 1


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


# ---------------------------------------------------------------------------
# A3: target_kind persisted on the canonical INSERT path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_persists_target_kind() -> None:
    """target_kind must be written to the audit row (regression for S2 MEDIUM).

    Before A3 the canonical INSERT was 9 columns and target_kind was
    accepted but dropped on the floor. The 10-column INSERT must place
    target_kind in the right positional slot for the dedup index to
    discriminate kinds.
    """
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="user",
        actor_id="00000000-0000-0000-0000-000000000001",
        action="entry.created",
        target_type="entry",
        target_id="00000000-0000-0000-0000-000000000042",
        target_kind=TargetKind.ENTRY,
    )
    sql, *args = conn.calls[0]
    assert sql == AUDIT_INSERT_SQL
    # 10-column layout: $1=actor_type $2=actor_id $3=action $4=target_type
    #                   $5=target_id $6=target_kind $7=reason $8=metadata
    #                   $9=ip_address $10=user_agent
    assert args[5] == TargetKind.ENTRY


# ---------------------------------------------------------------------------
# A3: record_audit_deduped_async wrapper
# ---------------------------------------------------------------------------


class _StubFetchvalConn:
    """Stub asyncpg.Connection capturing fetchval() calls.

    fetchval returns 1 on insert (RETURNING 1), None when ON CONFLICT
    skipped the write. Tests can prime the return value via
    ``fetchval_returns``.
    """

    def __init__(self, fetchval_returns: int | None = 1) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self._returns = fetchval_returns

    async def fetchval(self, sql: str, *args: Any) -> int | None:
        self.calls.append((sql, *args))
        return self._returns


@pytest.mark.unit
def test_record_audit_deduped_async_signature_is_kw_only() -> None:
    sig = inspect.signature(record_audit_deduped_async)
    params = list(sig.parameters.values())
    assert params[0].name == "conn"
    for p in params[1:]:
        assert p.kind == inspect.Parameter.KEYWORD_ONLY


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_deduped_async_writes_deduped_sql() -> None:
    """The dedup writer must route through AUDIT_INSERT_DEDUPED_SQL.

    Layout: (sql, actor_type, actor_id, action, target_kind, target_type,
    target_id, metadata_json).
    """
    conn = _StubFetchvalConn(fetchval_returns=1)
    inserted = await record_audit_deduped_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:stripe_webhook",
        action="subscription.created",
        target_kind=TargetKind.SUBSCRIPTION,
        target_type="subscription",
        target_id="sub_abc",
        metadata={"content_hash": "abc123"},
    )
    assert inserted is True
    assert len(conn.calls) == 1
    sql, *args = conn.calls[0]
    assert sql == AUDIT_INSERT_DEDUPED_SQL
    assert args[0] == "system"
    assert args[1] == "system:stripe_webhook"
    assert args[2] == "subscription.created"
    assert args[3] == TargetKind.SUBSCRIPTION
    assert args[4] == "subscription"
    assert args[5] == "sub_abc"
    assert json.loads(args[6]) == {"content_hash": "abc123"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_deduped_async_returns_false_on_conflict() -> None:
    """When ON CONFLICT skips the row, fetchval returns None -> wrapper returns False."""
    conn = _StubFetchvalConn(fetchval_returns=None)
    inserted = await record_audit_deduped_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:stripe_webhook",
        action="subscription.created",
        target_kind=TargetKind.SUBSCRIPTION,
        target_id="sub_abc",
        metadata={"content_hash": "abc123"},
    )
    assert inserted is False


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_deduped_async_validates_actor_id() -> None:
    """Same _validate_audit_id surface as record_audit_async."""
    conn = _StubFetchvalConn()
    with pytest.raises(ValueError, match="actor_id"):
        await record_audit_deduped_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="stripe_webhook",  # NOT a UUID, NOT prefixed -- footgun
            action="subscription.created",
            target_kind=TargetKind.SUBSCRIPTION,
            target_id="sub_abc",
            metadata={"content_hash": "abc"},
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_deduped_async_redacts_banned_metadata() -> None:
    conn = _StubFetchvalConn()
    await record_audit_deduped_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:stripe_webhook",
        action="subscription.created",
        target_kind=TargetKind.SUBSCRIPTION,
        target_id="sub_abc",
        metadata={"content_hash": "abc", "password": "leak"},
    )
    _, *args = conn.calls[0]
    persisted = json.loads(args[6])
    assert persisted["password"] == "[REDACTED]"
    assert persisted["content_hash"] == "abc"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_deduped_async_rejects_oversize_metadata() -> None:
    conn = _StubFetchvalConn()
    payload = {"content_hash": "x", **{f"item_{i}": "y" * 100 for i in range(50)}}
    with pytest.raises(ValueError, match="metadata exceeds"):
        await record_audit_deduped_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:stripe_webhook",
            action="subscription.created",
            target_kind=TargetKind.SUBSCRIPTION,
            target_id="sub_abc",
            metadata=payload,
        )
    assert conn.calls == []


# ---------------------------------------------------------------------------
# M-1 (R2): target_kind shape validation
#
# ``TargetKind`` is the single source of truth (see
# ``gubbi_common/audit/targets.py``). A typo string like ``"usr"`` or an
# empty string would otherwise persist verbatim and silently corrupt
# dedup grouping (the partial unique index keys on ``target_kind``) plus
# forensic queries that filter by kind. Validate at the boundary so the
# invariant cannot be bypassed by a misspelled call site.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_rejects_typo_target_kind_string() -> None:
    """A typoed target_kind string (``"usr"``) is rejected at the boundary."""
    conn = _StubConn()
    with pytest.raises(ValueError, match="Invalid target_kind"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:worker",
            action="identity.created",
            target_id="00000000-0000-0000-0000-000000000001",
            target_kind="usr",  # typo of "user"
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_rejects_empty_target_kind_string() -> None:
    """An empty ``target_kind`` string is rejected at the boundary."""
    conn = _StubConn()
    with pytest.raises(ValueError, match="Invalid target_kind"):
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:worker",
            action="identity.created",
            target_id="00000000-0000-0000-0000-000000000001",
            target_kind="",
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_accepts_valid_target_kind_string() -> None:
    """A bare string equal to a TargetKind.value is accepted.

    Some call sites pass the string form for legacy or codegen reasons;
    the validator must continue to accept them as long as the string
    matches one of ``TargetKind``'s ``.value`` strings.
    """
    conn = _StubConn()
    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="identity.created",
        target_id="00000000-0000-0000-0000-000000000001",
        target_kind="user",  # bare string equal to TargetKind.USER.value
    )
    assert len(conn.calls) == 1


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_deduped_async_rejects_typo_target_kind_string() -> None:
    """Same invariant on the dedup writer."""
    conn = _StubFetchvalConn()
    with pytest.raises(ValueError, match="Invalid target_kind"):
        await record_audit_deduped_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:stripe_webhook",
            action="subscription.created",
            target_kind="subscriptn",  # typo of "subscription"
            target_id="sub_abc",
            metadata={"content_hash": "abc"},
        )
    assert conn.calls == []


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_deduped_async_rejects_empty_target_kind_string() -> None:
    """Empty target_kind string on the dedup writer is rejected."""
    conn = _StubFetchvalConn()
    with pytest.raises(ValueError, match="Invalid target_kind"):
        await record_audit_deduped_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:stripe_webhook",
            action="subscription.created",
            target_kind="",
            target_id="sub_abc",
            metadata={"content_hash": "abc"},
        )
    assert conn.calls == []


# ---------------------------------------------------------------------------
# correlation_id kwarg + ContextVar default
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_threads_correlation_id_kwarg_into_metadata() -> None:
    """Explicit correlation_id kwarg lands in the JSON-encoded metadata."""
    conn = _StubConn()

    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="entry.created",
        metadata={"foo": "bar"},
        correlation_id="req-explicit-7a3e",
    )

    payload = json.loads(conn.calls[0][8])  # metadata is $8 (index 7 in args, 8 in call tuple)
    assert payload == {"foo": "bar", "correlation_id": "req-explicit-7a3e"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_picks_up_correlation_id_from_contextvar() -> None:
    """Caller omits the kwarg -> default sourced from get_correlation_id()."""
    from gubbi_common.correlation import reset_correlation_id, set_correlation_id

    conn = _StubConn()
    token = set_correlation_id("req-ctxvar-c91d")
    try:
        await record_audit_async(
            conn,  # type: ignore[arg-type]
            actor_type="system",
            actor_id="system:worker",
            action="entry.created",
            metadata={"foo": "bar"},
        )
    finally:
        reset_correlation_id(token)

    payload = json.loads(conn.calls[0][8])
    assert payload == {"foo": "bar", "correlation_id": "req-ctxvar-c91d"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_caller_metadata_correlation_id_wins() -> None:
    """Explicit caller-supplied metadata['correlation_id'] is NOT overwritten.

    Defense against silently replacing a deliberately-chosen value (e.g. a
    test fixture pinning a specific cid for assertion).
    """
    conn = _StubConn()

    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="entry.created",
        metadata={"correlation_id": "caller-wins"},
        correlation_id="kwarg-should-not-win",
    )

    payload = json.loads(conn.calls[0][8])
    assert payload == {"correlation_id": "caller-wins"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_async_no_correlation_id_when_context_unset() -> None:
    """No kwarg + ContextVar unset -> metadata has NO correlation_id key."""
    conn = _StubConn()

    await record_audit_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:worker",
        action="entry.created",
        metadata={"foo": "bar"},
    )

    payload = json.loads(conn.calls[0][8])
    assert payload == {"foo": "bar"}
    assert "correlation_id" not in payload


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_audit_deduped_async_threads_correlation_id_into_metadata() -> None:
    """Dedup writer mirrors the canonical writer's correlation_id semantics.

    Logic is shared via ``_prepare_metadata``; this pins the contract on
    the dedup path so a future refactor that bypasses the helper for
    dedup writes is caught.
    """
    conn = _StubFetchvalConn(fetchval_returns=1)

    await record_audit_deduped_async(
        conn,  # type: ignore[arg-type]
        actor_type="system",
        actor_id="system:stripe_webhook",
        action="subscription.created",
        target_kind=TargetKind.SUBSCRIPTION,
        target_id="sub_abc",
        metadata={"content_hash": "abc123"},
        correlation_id="req-dedup-cid-99",
    )

    # Dedup writer parameter layout puts metadata at args index 6
    # (sql=[0], actor_type=[1], actor_id=[2], action=[3],
    #  target_kind=[4], target_type=[5], target_id=[6], metadata=[7]).
    # _StubFetchvalConn captures (sql, *args) flat in calls[0], so
    # metadata is conn.calls[0][7].
    payload = json.loads(conn.calls[0][7])
    assert payload == {"content_hash": "abc123", "correlation_id": "req-dedup-cid-99"}
