"""Integration tests for ``AUDIT_INSERT_DEDUPED_SQL``.

Run with ``INTEGRATION=1 pytest -m integration``. Uses the testcontainers
``pg_pool`` fixture from ``tests/integration/conftest.py``. The vendored
schema (``AUDIT_LOG_DDL``) mirrors gubbi migrations through 0022; the
``AUDIT_LOG_DDL_BASED_ON`` constant pins the high-water mark and is
guarded by ``test_audit_ddl_based_on_matches_latest_migration`` in
``test_audit_schema_drift.py``. Update conftest and the based-on pin
together when audit_log migrations land.

Each test runs without an outer transaction so the dedup
``ON CONFLICT`` path is exercised against the actual partial unique
index, not against rows that get rolled back at function exit. The
``_audit_log_clean`` fixture wipes ``audit_log`` between tests; the
explicit truncate is the cleanup contract -- relying on
``conn.transaction()`` rollback would mean the second-call dedup test
never actually exercised the conflict path because the first INSERT
would never have committed.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from gubbi_common.audit import TargetKind
from gubbi_common.audit.sql import AUDIT_INSERT_DEDUPED_SQL

if TYPE_CHECKING:
    import asyncpg


pytestmark = pytest.mark.integration


@pytest_asyncio.fixture(loop_scope="session")
async def _audit_log_clean(pg_pool: asyncpg.Pool) -> AsyncIterator[None]:
    """Wipe ``audit_log`` after each test.

    Why explicit DELETE instead of ``conn.transaction()`` rollback: the
    dedup tests need to commit the first INSERT so the partial unique
    index sees the row. A rollback would discard the row and the
    second INSERT would no longer trip the index, masking a regression
    in the dedup contract. The fixture pays a small per-test
    delete-everything cost in exchange for correct semantics.
    """
    yield
    async with pg_pool.acquire() as conn:
        await conn.execute("DELETE FROM audit_log")


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.usefixtures("_audit_log_clean")
async def test_dedup_insert_inserts_first_row(pg_pool: asyncpg.Pool) -> None:
    async with pg_pool.acquire() as conn:
        result = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000001",
            json.dumps({"content_hash": "abc"}),
        )
        assert result == 1


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.usefixtures("_audit_log_clean")
async def test_dedup_insert_blocks_duplicate_content_hash(
    pg_pool: asyncpg.Pool,
) -> None:
    async with pg_pool.acquire() as conn:
        first = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000002",
            json.dumps({"content_hash": "dup"}),
        )
        assert first == 1

        # Second call with same (target_kind, target_id, action,
        # content_hash) hits the partial unique index; ON CONFLICT DO
        # NOTHING returns no row.
        second = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000002",
            json.dumps({"content_hash": "dup"}),
        )
        assert second is None


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.usefixtures("_audit_log_clean")
async def test_dedup_insert_allows_different_content_hash(
    pg_pool: asyncpg.Pool,
) -> None:
    async with pg_pool.acquire() as conn:
        first = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000003",
            json.dumps({"content_hash": "h1"}),
        )
        second = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000003",
            json.dumps({"content_hash": "h2"}),
        )
        assert first == 1
        assert second == 1


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.usefixtures("_audit_log_clean")
async def test_dedup_insert_no_content_hash_does_not_dedup(
    pg_pool: asyncpg.Pool,
) -> None:
    """The partial index has WHERE metadata ? 'content_hash'; rows that
    omit ``content_hash`` skip the index entirely and never collide."""
    async with pg_pool.acquire() as conn:
        first = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000004",
            json.dumps({"other": "value"}),
        )
        second = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000004",
            json.dumps({"other": "value"}),
        )
        assert first == 1
        assert second == 1


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.usefixtures("_audit_log_clean")
async def test_dedup_distinguishes_target_kinds(pg_pool: asyncpg.Pool) -> None:
    """Cross-namespace collision avoidance: same ``(target_id, action,
    content_hash)`` with different ``target_kind`` must both insert.

    This is the regression test for the motivation behind migration
    0020: the dedup partial unique index includes ``target_kind`` as the
    leading column so heterogeneous ``target_id`` shapes across kinds
    (e.g. a user id and a subscription id that happen to share the same
    literal string) cannot trip a false unique-violation.
    """
    async with pg_pool.acquire() as conn:
        # Use distinct target_kind vs target_type values so a swapped-bind
        # regression in AUDIT_INSERT_DEDUPED_SQL ($4 <-> $5) shows up in
        # the post-insert assertion below; if both columns received the
        # same string the swap would be invisible.
        first = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            TargetKind.USER,  # $4 target_kind
            "kratos_identity",  # $5 target_type (deliberately != target_kind value)
            "dup-id",
            json.dumps({"content_hash": "x"}),
        )
        assert first == 1

        # Same target_id + action + content_hash but a different
        # target_kind -- the partial unique index keys on target_kind
        # first, so this must succeed rather than collide.
        second = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            TargetKind.SUBSCRIPTION,  # $4 target_kind
            "stripe_subscription",  # $5 target_type (deliberately != target_kind value)
            "dup-id",
            json.dumps({"content_hash": "x"}),
        )
        assert second == 1

        count = await conn.fetchval("SELECT count(*) FROM audit_log WHERE target_id = 'dup-id'")
        assert count == 2

        # Confirm BOTH rows persisted distinct (target_kind, target_type)
        # values. With the column-distinct values above, this catches a
        # swapped $4/$5 column-order regression: the swap would surface
        # as target_kind="kratos_identity"/"stripe_subscription" instead
        # of "user"/"subscription", failing both ordering assertions.
        rows = await conn.fetch(
            "SELECT target_kind, target_type FROM audit_log "
            "WHERE target_id = 'dup-id' ORDER BY target_kind"
        )
        kinds = [row["target_kind"] for row in rows]
        types = [row["target_type"] for row in rows]
        assert kinds == [TargetKind.SUBSCRIPTION, TargetKind.USER]
        assert types == ["stripe_subscription", "kratos_identity"]


# Sibling-repo path; ``conftest.MIGRATION_DDL_PATH`` does the resolution.
# Pins to migration 0020 (target_kind rebuild) -- the migration that
# defines the index shape ``AUDIT_INSERT_DEDUPED_SQL`` now depends on.
# The old 0016 glob was a no-op guard: it asserted the OLD 3-column
# index name lived in mig 0016 (true, but unrelated to today's shape).
_GUBBI_MIGRATION_GLOB = "*0020*audit_log_target_kind*.py"


def _gubbi_migration_path() -> Path | None:
    from tests.integration.conftest import MIGRATION_DDL_PATH

    if not MIGRATION_DDL_PATH.exists():
        return None
    matches = list(MIGRATION_DDL_PATH.glob(_GUBBI_MIGRATION_GLOB))
    return matches[0] if matches else None


@pytest.mark.asyncio(loop_scope="session")
async def test_dedup_ddl_matches_gubbi_migration(pg_pool: asyncpg.Pool) -> None:
    """Cross-check the live partial-index DDL against gubbi migration 0020.

    Skips if gubbi is not checked out alongside gubbi-common (e.g. CI
    that runs only this repo). When gubbi is present, the migration
    string must carry the partial index name, the new leading column
    ``target_kind``, and the ``content_hash`` predicate that the dedup
    INSERT relies on. This is the real cross-check; the previous shape
    (against mig 0016) was a no-op.
    """
    path = _gubbi_migration_path()
    if path is None:
        pytest.skip("gubbi migration 0020 not present alongside gubbi-common")

    text = path.read_text(encoding="utf-8")
    # Three contract surfaces: index name, leading column, partial predicate.
    # All three must be present in the migration that builds the index
    # AUDIT_INSERT_DEDUPED_SQL targets.
    assert "audit_log_content_hash_uidx" in text, (
        "gubbi migration 0020 no longer carries the dedup index name; "
        "AUDIT_INSERT_DEDUPED_SQL is broken"
    )
    assert "target_kind" in text, (
        "gubbi migration 0020 dropped target_kind from the dedup index; "
        "AUDIT_INSERT_DEDUPED_SQL ON CONFLICT no longer matches"
    )
    assert "content_hash" in text
