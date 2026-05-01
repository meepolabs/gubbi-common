"""Tests for gubbi_common.db.user_scoped."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, call
from uuid import uuid4

import pytest

from gubbi_common.db.user_scoped import MissingUserIdError, user_scoped_connection


def make_pool() -> tuple[Any, Any]:
    """Create a mock asyncpg pool and connection for testing."""
    conn = MagicMock()
    conn.execute = AsyncMock()
    txn = MagicMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool, conn


class TestMissingUserIdError:
    def test_is_runtime_error(self) -> None:
        assert issubclass(MissingUserIdError, RuntimeError)


class TestUserScopedConnection:
    @pytest.mark.asyncio
    async def test_raises_missing_user_id_when_none(self) -> None:
        pool, _ = make_pool()
        with pytest.raises(MissingUserIdError, match="requires a user_id"):
            async with user_scoped_connection(pool, None):  # type: ignore[arg-type]
                pass  # pragma: no cover

    @pytest.mark.asyncio
    async def test_raises_type_error_when_not_uuid(self) -> None:
        pool, _ = make_pool()
        with pytest.raises(TypeError, match="user_id must be UUID"):
            async with user_scoped_connection(pool, "not-a-uuid"):  # type: ignore[arg-type]
                pass  # pragma: no cover

    @pytest.mark.parametrize("bad_value", [0, -1, 1001, 9999])
    @pytest.mark.asyncio
    async def test_raises_value_error_when_hnsw_out_of_range(self, bad_value: int) -> None:
        pool, _ = make_pool()
        uid = uuid4()
        with pytest.raises(ValueError, match=r"hnsw_ef_search must be in \[1, 1000\]"):
            async with user_scoped_connection(pool, uid, hnsw_ef_search=bad_value):
                pass  # pragma: no cover

    @pytest.mark.asyncio
    async def test_sets_both_gucs_on_happy_path(self) -> None:
        pool, conn = make_pool()
        uid = uuid4()

        async with user_scoped_connection(pool, uid) as yielded_conn:
            assert yielded_conn is conn

        assert conn.execute.call_count == 2
        user_id_call = conn.execute.call_args_list[0]
        ef_search_call = conn.execute.call_args_list[1]

        assert user_id_call == call(
            "SELECT set_config('app.current_user_id', $1, true)",
            str(uid),
        )
        assert ef_search_call == call(
            "SELECT set_config('hnsw.ef_search', $1, true)",
            "100",
        )

    @pytest.mark.asyncio
    async def test_transaction_committed_on_clean_exit(self) -> None:
        pool, conn = make_pool()
        uid = uuid4()

        async with user_scoped_connection(pool, uid):
            pass

        conn.transaction.return_value.__aexit__.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_gucs_set_when_exception_raised_inside_context(self) -> None:
        pool, conn = make_pool()
        uid = uuid4()

        with pytest.raises(RuntimeError, match="something went wrong"):
            async with user_scoped_connection(pool, uid):
                raise RuntimeError("something went wrong")

        # GUCs should have been set before the exception
        assert conn.execute.await_count == 2
        # Transaction should still exit (cleanup)
        conn.transaction.return_value.__aexit__.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_concurrent_isolation(self) -> None:
        """Two concurrent scoped connections with different user_ids each get correct GUCs."""
        pool1, conn1 = make_pool()
        pool2, conn2 = make_pool()
        uid1 = uuid4()
        uid2 = uuid4()

        async def scope1() -> None:
            async with user_scoped_connection(pool1, uid1):
                pass

        async def scope2() -> None:
            async with user_scoped_connection(pool2, uid2):
                pass

        await asyncio.gather(scope1(), scope2())

        # Verify conn1 got uid1
        assert conn1.execute.await_count == 2
        conn1_first_call = conn1.execute.call_args_list[0]
        assert conn1_first_call == call(
            "SELECT set_config('app.current_user_id', $1, true)",
            str(uid1),
        )

        # Verify conn2 got uid2
        assert conn2.execute.await_count == 2
        conn2_first_call = conn2.execute.call_args_list[0]
        assert conn2_first_call == call(
            "SELECT set_config('app.current_user_id', $1, true)",
            str(uid2),
        )
