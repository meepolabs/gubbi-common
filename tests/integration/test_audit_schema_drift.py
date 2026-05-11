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
    """Return columns that are NOT NULL and have no default -- the INSERT must supply them."""
    rows = await conn.fetch(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'audit_log'
          AND is_nullable = 'NO'
          AND column_default IS NULL
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
