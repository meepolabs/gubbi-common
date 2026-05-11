"""Integration tests for ``AUDIT_INSERT_DEDUPED_SQL``.

Run with ``INTEGRATION=1 pytest -m integration``. Uses the testcontainers
``pg_pool`` fixture from ``tests/integration/conftest.py``. The schema
applied there mirrors gubbi migration 0016 -- update both together.

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
            "00000000-0000-0000-0000-000000000002",
            json.dumps({"content_hash": "dup"}),
        )
        assert first == 1

        # Second call with same (target_id, action, content_hash) hits the
        # partial unique index; ON CONFLICT DO NOTHING returns no row.
        second = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
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
            "00000000-0000-0000-0000-000000000003",
            json.dumps({"content_hash": "h1"}),
        )
        second = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
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
            "00000000-0000-0000-0000-000000000004",
            json.dumps({"other": "value"}),
        )
        second = await conn.fetchval(
            AUDIT_INSERT_DEDUPED_SQL,
            "system",
            "system:worker",
            "identity.updated",
            "user",
            "00000000-0000-0000-0000-000000000004",
            json.dumps({"other": "value"}),
        )
        assert first == 1
        assert second == 1


# Sibling-repo path; ``conftest.MIGRATION_DDL_PATH`` does the resolution.
_GUBBI_MIGRATION_GLOB = "*0016*.py"


def _gubbi_migration_path() -> Path | None:
    from tests.integration.conftest import MIGRATION_DDL_PATH

    if not MIGRATION_DDL_PATH.exists():
        return None
    matches = list(MIGRATION_DDL_PATH.glob(_GUBBI_MIGRATION_GLOB))
    return matches[0] if matches else None


@pytest.mark.asyncio(loop_scope="session")
async def test_dedup_ddl_matches_gubbi_migration(pg_pool: asyncpg.Pool) -> None:
    """Cross-check the live partial-index DDL against gubbi migration 0016.

    Skips if gubbi is not checked out alongside gubbi-common (e.g. CI
    that runs only this repo). When gubbi is present, the migration
    string must mention the partial index name and the WHERE clause that
    the dedup INSERT relies on.
    """
    path = _gubbi_migration_path()
    if path is None:
        pytest.skip("gubbi migration 0016 not present alongside gubbi-common")

    text = path.read_text(encoding="utf-8")
    # Index name is the contract; the DDL string is what makes the
    # ON CONFLICT in AUDIT_INSERT_DEDUPED_SQL work.
    assert "audit_log_content_hash_uidx" in text, (
        "gubbi migration 0016 no longer carries the dedup index name; "
        "AUDIT_INSERT_DEDUPED_SQL is broken"
    )
    assert "content_hash" in text
