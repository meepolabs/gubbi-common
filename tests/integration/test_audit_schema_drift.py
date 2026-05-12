"""Integration tests guarding against ``audit_log`` schema drift.

Each ``AUDIT_INSERT_*`` SQL constant in ``gubbi_common.audit.sql``
hard-codes a column list. If the table evolves (column added, NOT NULL
flipped on, default removed) and the constant is not updated, INSERTs
silently break in production. These tests parse the column list from
each constant, query ``information_schema.columns`` for the live table,
and assert every NOT-NULL column without a default is present in the
INSERT.

NULL-able columns and columns with a default value are allowed to be
omitted -- those are the cases where the database fills in the value
itself. Columns the INSERT supplies that do not exist in the table also
fail the test; the INSERT would error at execute time.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from gubbi_common.audit.sql import (
    AUDIT_INSERT_DEDUPED_SQL,
    AUDIT_INSERT_SHORT_SQL,
    AUDIT_INSERT_SQL,
    AUDIT_INSERT_SQL_RICH,
)

if TYPE_CHECKING:
    import asyncpg


pytestmark = pytest.mark.integration


# Match the parenthesised column list in ``INSERT INTO audit_log (col, col, ...)``.
_COLS_RE = re.compile(
    r"INSERT\s+INTO\s+audit_log\s*\((?P<cols>[^)]+)\)",
    re.IGNORECASE | re.DOTALL,
)


def _parse_inserted_columns(sql: str) -> set[str]:
    match = _COLS_RE.search(sql)
    assert match is not None, f"could not parse audit_log column list from SQL:\n{sql}"
    raw = match.group("cols")
    return {col.strip() for col in raw.split(",") if col.strip()}


async def _fetch_required_columns(conn: asyncpg.Connection) -> set[str]:
    """Return columns that are NOT NULL and have no default -- the INSERT must supply them.

    ``GENERATED ALWAYS AS IDENTITY`` columns report ``column_default``
    NULL but the database generates the value itself; treat them as
    "not required" the same way we treat columns with a literal
    DEFAULT.
    """
    rows = await conn.fetch(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'audit_log'
          AND is_nullable = 'NO'
          AND column_default IS NULL
          AND is_identity = 'NO'
        """
    )
    return {row["column_name"] for row in rows}


async def _fetch_all_columns(conn: asyncpg.Connection) -> set[str]:
    rows = await conn.fetch(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'audit_log'
        """
    )
    return {row["column_name"] for row in rows}


async def _assert_insert_covers_required(conn: asyncpg.Connection, sql: str) -> None:
    inserted = _parse_inserted_columns(sql)
    required = await _fetch_required_columns(conn)
    all_cols = await _fetch_all_columns(conn)

    missing = required - inserted
    assert not missing, (
        f"INSERT does not supply NOT-NULL columns {sorted(missing)}; "
        f"audit_log has drifted from the SQL constant"
    )

    unknown = inserted - all_cols
    assert not unknown, (
        f"INSERT references columns {sorted(unknown)} not present in audit_log; "
        f"the INSERT would fail at execute time"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_audit_insert_sql_covers_all_audit_log_columns(pg_pool: asyncpg.Pool) -> None:
    async with pg_pool.acquire() as conn:
        await _assert_insert_covers_required(conn, AUDIT_INSERT_SQL)


@pytest.mark.asyncio(loop_scope="session")
async def test_audit_insert_short_sql_covers_required_columns(pg_pool: asyncpg.Pool) -> None:
    async with pg_pool.acquire() as conn:
        await _assert_insert_covers_required(conn, AUDIT_INSERT_SHORT_SQL)


@pytest.mark.asyncio(loop_scope="session")
async def test_audit_insert_sql_rich_covers_required_columns(pg_pool: asyncpg.Pool) -> None:
    async with pg_pool.acquire() as conn:
        await _assert_insert_covers_required(conn, AUDIT_INSERT_SQL_RICH)


@pytest.mark.asyncio(loop_scope="session")
async def test_audit_insert_deduped_sql_covers_required_columns(pg_pool: asyncpg.Pool) -> None:
    async with pg_pool.acquire() as conn:
        await _assert_insert_covers_required(conn, AUDIT_INSERT_DEDUPED_SQL)


# ---------------------------------------------------------------------------
# Partial-unique-index column composition drift guard (mig 0020).
# ---------------------------------------------------------------------------
# The ``audit_log_content_hash_uidx`` partial unique index is the
# substrate for ``AUDIT_INSERT_DEDUPED_SQL``'s ON CONFLICT clause. Its
# column composition is keyed on
# ``(target_kind, target_id, action, metadata->>'content_hash')`` with
# the partial predicate ``WHERE metadata ? 'content_hash'``. A future
# migration that rebuilds this index with a different column order or
# predicate would silently break dedup at write time (42P10) without
# this test firing.
_EXPECTED_INDEX_COL_TUPLE: tuple[str, str, str, str] = (
    "target_kind",
    "target_id",
    "action",
    "metadata ->> 'content_hash'",
)


@pytest.mark.asyncio(loop_scope="session")
async def test_dedup_unique_index_column_composition(pg_pool: asyncpg.Pool) -> None:
    """Pin the 4-tuple of columns / expressions on ``audit_log_content_hash_uidx``.

    Walks ``pg_index.indkey`` and resolves attnums via ``pg_attribute``;
    indexed expressions (attnum=0) are rendered via
    ``pg_get_indexdef(indexrelid, position, true)``. The last element of
    the 4-tuple is an expression (``metadata->>'content_hash'``);
    asserted via substring match because the renderer's exact whitespace
    is not stable across PG versions. The partial predicate is asserted
    via ``pg_get_expr(indpred, indrelid)`` substring on
    ``metadata ? 'content_hash'``.
    """
    async with pg_pool.acquire() as conn:
        # Pull the ordered (attnum, position) pairs from pg_index.
        rows = await conn.fetch(
            """
            SELECT
                a.position,
                i.indkey[a.position - 1] AS attnum,
                CASE
                    WHEN i.indkey[a.position - 1] = 0
                        THEN pg_get_indexdef(i.indexrelid, a.position::int, true)
                    ELSE (
                        SELECT attname
                        FROM pg_attribute
                        WHERE attrelid = i.indrelid
                          AND attnum = i.indkey[a.position - 1]
                    )
                END AS rendered
            FROM pg_index i,
                 generate_series(1, array_length(i.indkey, 1)) AS a(position)
            WHERE i.indexrelid = 'audit_log_content_hash_uidx'::regclass
            ORDER BY a.position
            """
        )
        rendered = [row["rendered"] for row in rows]
        assert len(rendered) == 4, (
            f"audit_log_content_hash_uidx has {len(rendered)} columns, " f"expected 4: {rendered}"
        )

        # First three are plain columns -- exact match.
        assert rendered[0] == _EXPECTED_INDEX_COL_TUPLE[0]
        assert rendered[1] == _EXPECTED_INDEX_COL_TUPLE[1]
        assert rendered[2] == _EXPECTED_INDEX_COL_TUPLE[2]

        # Fourth is the metadata->>'content_hash' expression; substring
        # match because PG renderer whitespace is not stable.
        assert "metadata" in rendered[3]
        assert "content_hash" in rendered[3]

        # Partial predicate must still be ``metadata ? 'content_hash'``.
        predicate = await conn.fetchval(
            """
            SELECT pg_get_expr(indpred, indrelid)
            FROM pg_index
            WHERE indexrelid = 'audit_log_content_hash_uidx'::regclass
            """
        )
        assert predicate is not None, "audit_log_content_hash_uidx is no longer a partial index"
        assert (
            "content_hash" in predicate
        ), f"partial predicate dropped 'content_hash' reference: {predicate!r}"
        # The jsonb key-exists operator ``?`` is the contract; a swap to
        # e.g. ``metadata->>'content_hash' IS NOT NULL`` would still
        # satisfy a substring check on 'content_hash' but change index
        # semantics. Pin the operator explicitly.
        assert (
            " ? " in predicate or "metadata ? " in predicate
        ), f"partial predicate operator drifted from jsonb '?': {predicate!r}"


# ---------------------------------------------------------------------------
# Based-on guard: AUDIT_LOG_DDL must reflect every audit_log migration up to
# the constant pinned in conftest.
# ---------------------------------------------------------------------------
# Glob-scans the gubbi sibling repo for ``*audit_log*.py`` Alembic
# revisions, parses the ``YYYYMMDD_NNNN`` prefix from each filename, and
# asserts the maximum is <= ``AUDIT_LOG_DDL_BASED_ON``. A newer
# migration than the pin means ``AUDIT_LOG_DDL`` in conftest is stale
# and dedup/drift tests are exercising a pre-migration shape.
_REV_PREFIX_RE = re.compile(r"^(\d{8}_\d{4})_")


def test_audit_ddl_based_on_matches_latest_migration() -> None:
    """Fail when ``AUDIT_LOG_DDL_BASED_ON`` is behind the latest gubbi audit_log migration.

    Skips when the gubbi sibling repo is not present alongside
    gubbi-common (e.g. CI that runs only this repo). When the sibling
    is present, every ``gubbi/alembic/versions/*audit_log*.py``
    revision must be <= ``AUDIT_LOG_DDL_BASED_ON``. If a newer revision
    has landed, refresh ``AUDIT_LOG_DDL`` in conftest.py to reflect it
    and bump ``AUDIT_LOG_DDL_BASED_ON`` to match.
    """
    from tests.integration.conftest import AUDIT_LOG_DDL_BASED_ON, MIGRATION_DDL_PATH

    if not MIGRATION_DDL_PATH.exists():
        pytest.skip("gubbi migrations not present alongside gubbi-common")

    matches = sorted(MIGRATION_DDL_PATH.glob("*audit_log*.py"))
    if not matches:
        pytest.skip("no gubbi audit_log migrations matched the glob")

    revs: list[str] = []
    for path in matches:
        m = _REV_PREFIX_RE.match(path.name)
        if m is None:
            continue
        revs.append(m.group(1))

    assert revs, f"could not parse any YYYYMMDD_NNNN prefix from {[p.name for p in matches]}"
    latest = max(revs)
    assert latest <= AUDIT_LOG_DDL_BASED_ON, (
        f"gubbi audit_log migration {latest!r} is newer than the vendored "
        f"AUDIT_LOG_DDL based-on pin {AUDIT_LOG_DDL_BASED_ON!r}. Refresh "
        "AUDIT_LOG_DDL in tests/integration/conftest.py to reflect the new "
        "migration and bump AUDIT_LOG_DDL_BASED_ON to match."
    )
