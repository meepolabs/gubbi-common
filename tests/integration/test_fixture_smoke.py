"""Smoke test for the testcontainers ``pg_pool`` fixture.

Runs only when ``INTEGRATION=1``. Confirms the container is reachable
and the asyncpg pool can execute a trivial query.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    import asyncpg


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.integration
async def test_pool_executes_select_one(pg_pool: asyncpg.Pool) -> None:
    async with pg_pool.acquire() as conn:
        value = await conn.fetchval("SELECT 1")
    assert value == 1
