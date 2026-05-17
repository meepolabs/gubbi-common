"""Integration tests for ``AUDIT_INSERT_DEDUPED_SQL``.

Run with ``INTEGRATION=1 pytest -m integration``. Uses the testcontainers
``pg_pool`` fixture from ``tests/integration/conftest.py``. The vendored
schema (``AUDIT_LOG_DDL``) mirrors gubbi migrations through 0031; the
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

        # Second call with same (actor_id, target_kind, target_id, action,
        # content_hash) hits the partial unique index; ON CONFLICT DO
        # NOTHING returns no row. Same actor_id is intentional -- the
        # mig-0031 index leads with actor_id, so a different actor_id
        # would no longer collide (see ``test_dedup_allows_cross_actor``).
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
    0020: the dedup partial unique index includes ``target_kind`` as a
    leading namespace column so heterogeneous ``target_id`` shapes
    across kinds (e.g. a user id and a subscription id that happen to
    share the same literal string) cannot trip a false unique-violation.
    Migration 0031 prepended ``actor_id`` ahead of ``target_kind``, but
    this test holds ``actor_id`` constant across both rows so the
    target_kind discriminator is the only thing distinguishing them.
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
        # target_kind -- the partial unique index keys on target_kind,
        # so this must succeed rather than collide. ``actor_id`` is held
        # constant across both rows so target_kind is the sole
        # discriminator under test.
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


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.usefixtures("_audit_log_clean")
async def test_dedup_allows_cross_actor(pg_pool: asyncpg.Pool) -> None:
    """Two different actors writing the same target tuple must BOTH succeed.

    Regression test for the bug-#3 / migration-0031 contract: the
    dedup partial unique index leads with ``actor_id`` so a malicious
    or buggy second actor cannot suppress an audit row written by a
    first actor by replaying the same
    ``(target_kind, target_id, action, content_hash)`` tuple.

    Pre-mig-0031 (actor_id NOT in the index), the second INSERT here
    would have collided with the first and ON CONFLICT DO NOTHING would
    have returned ``None``, silently swallowing the second actor's
    audit trail. Post-mig-0031, both rows persist because the leading
    ``actor_id`` column distinguishes them.
    """
    async with pg_pool.acquire() as conn:
        first = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker_one",  # $2 actor_id
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000005",
            json.dumps({"content_hash": "shared"}),
        )
        assert first == 1

        # Same (target_kind, target_id, action, content_hash) tuple but
        # a different actor_id -- post-mig-0031 the leading actor_id
        # column means this is a separate dedup namespace and the row
        # MUST insert.
        second = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker_two",  # $2 actor_id (different)
            "identity.updated",
            "user",
            "user",
            "00000000-0000-0000-0000-000000000005",
            json.dumps({"content_hash": "shared"}),
        )
        assert second == 1

        count = await conn.fetchval(
            "SELECT count(*) FROM audit_log "
            "WHERE target_id = '00000000-0000-0000-0000-000000000005'"
        )
        assert count == 2

        # Confirm both rows carry their distinct actor_id values --
        # catches a regression that drops ``actor_id`` from the dedup
        # index but leaves the test passing because the duplicate row
        # was silently suppressed.
        rows = await conn.fetch(
            "SELECT actor_id FROM audit_log "
            "WHERE target_id = '00000000-0000-0000-0000-000000000005' "
            "ORDER BY actor_id"
        )
        actor_ids = [row["actor_id"] for row in rows]
        assert actor_ids == ["system:worker_one", "system:worker_two"]


# Sibling-repo path; ``conftest.MIGRATION_DDL_PATH`` does the resolution.
# Pins to migration 0031 (actor_id prepend) -- the migration that
# defines the index shape ``AUDIT_INSERT_DEDUPED_SQL`` now depends on.
# The previous 0020 glob was retained until 0031 landed; cross-checking
# the latest migration is the contract this guard enforces.
_GUBBI_MIGRATION_GLOB = "*0031*audit_log_dedup_actor_scope*.py"


def _gubbi_migration_path() -> Path | None:
    from tests.integration.conftest import MIGRATION_DDL_PATH

    if not MIGRATION_DDL_PATH.exists():
        return None
    matches = list(MIGRATION_DDL_PATH.glob(_GUBBI_MIGRATION_GLOB))
    return matches[0] if matches else None


@pytest.mark.asyncio(loop_scope="session")
async def test_dedup_ddl_matches_gubbi_migration(pg_pool: asyncpg.Pool) -> None:
    """Cross-check the live partial-index DDL against gubbi migration 0031.

    Skips if gubbi is not checked out alongside gubbi-common (e.g. CI
    that runs only this repo). When gubbi is present, the migration
    string must carry the partial index name, the leading column
    ``actor_id`` (from mig 0031), the namespace discriminator
    ``target_kind`` (from mig 0020), and the ``content_hash`` predicate
    that the dedup INSERT relies on.
    """
    path = _gubbi_migration_path()
    if path is None:
        pytest.skip("gubbi migration 0031 not present alongside gubbi-common")

    text = path.read_text(encoding="utf-8")
    # Four contract surfaces: index name, leading actor_id (mig 0031),
    # target_kind namespace discriminator, partial predicate.
    assert "audit_log_content_hash_uidx" in text, (
        "gubbi migration 0031 no longer carries the dedup index name; "
        "AUDIT_INSERT_DEDUPED_SQL is broken"
    )
    assert "actor_id" in text, (
        "gubbi migration 0031 dropped actor_id from the dedup index; "
        "AUDIT_INSERT_DEDUPED_SQL ON CONFLICT no longer matches"
    )
    assert "target_kind" in text, (
        "gubbi migration 0031 dropped target_kind from the dedup index; "
        "AUDIT_INSERT_DEDUPED_SQL ON CONFLICT no longer matches"
    )
    assert "content_hash" in text
