"""Tests for ``user_scoped_connection_readonly``.

The readonly variant is purpose-built for read paths (semantic search,
list endpoints) where opening a transaction would only add latency and
contention. It applies the same RLS prologue but stays in autocommit and
uses session-scoped ``set_config(..., false)`` so the GUC value persists
across statements within the connection -- with a matching ``RESET`` in
the finally block to keep the value out of the next pool checkout.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from gubbi_common.db.user_scoped import (
    DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS,
    user_scoped_connection_readonly,
)


def make_pool() -> tuple[Any, Any]:
    conn = MagicMock()
    conn.execute = AsyncMock()
    conn.transaction = MagicMock()
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool, conn


@pytest.mark.asyncio
async def test_readonly_no_transaction_opened() -> None:
    pool, conn = make_pool()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid):
        pass

    conn.transaction.assert_not_called()


@pytest.mark.asyncio
async def test_readonly_uses_session_scope_set_config() -> None:
    """``set_config(..., false)`` is the session-scope form."""
    pool, conn = make_pool()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid):
        pass

    sqls = [c.args[0] for c in conn.execute.call_args_list]
    assert any("set_config('app.current_user_id'" in s and "false" in s for s in sqls)
    assert any("set_config('hnsw.ef_search'" in s and "false" in s for s in sqls)


@pytest.mark.asyncio
async def test_readonly_resets_on_exit_load_bearing() -> None:
    """RESET on clean exit returns the connection to the pool with a
    pristine session, preventing GUC bleed across checkouts."""
    pool, conn = make_pool()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid):
        pass

    sqls = [c.args[0] for c in conn.execute.call_args_list]
    assert "RESET app.current_user_id" in sqls
    assert "RESET hnsw.ef_search" in sqls


@pytest.mark.asyncio
async def test_readonly_resets_on_exception() -> None:
    pool, conn = make_pool()
    uid = uuid4()

    with pytest.raises(RuntimeError, match="boom"):
        async with user_scoped_connection_readonly(pool, uid):
            raise RuntimeError("boom")

    sqls = [c.args[0] for c in conn.execute.call_args_list]
    assert "RESET app.current_user_id" in sqls
    assert "RESET hnsw.ef_search" in sqls


@pytest.mark.asyncio
async def test_readonly_happy_path_yields_conn() -> None:
    pool, conn = make_pool()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid) as yielded:
        assert yielded is conn


# ===========================================================================
# A-M4: SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY enforcement
# ===========================================================================


@pytest.mark.asyncio
async def test_readonly_sets_transaction_read_only_before_gucs() -> None:
    """A-M4: the read-only declaration runs BEFORE the GUC prologue.

    Without this ordering, an erroring set_config call could leak a
    writable session for the duration of the with-block (which is
    exactly what the docstring previously promised, falsely).
    """
    pool, conn = make_pool()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid):
        pass

    sqls = [c.args[0] for c in conn.execute.call_args_list]
    assert sqls, "expected at least one execute call"
    # First call must be the read-only declaration.
    assert (
        sqls[0] == "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"
    ), f"expected read-only declaration first, got {sqls[0]!r}"
    # And it precedes the user-id set_config.
    user_id_idx = next(i for i, s in enumerate(sqls) if "app.current_user_id" in s)
    read_only_idx = sqls.index("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
    assert read_only_idx < user_id_idx


@pytest.mark.asyncio
async def test_readonly_clears_read_only_on_exit() -> None:
    """A-M4: cleanup restores READ WRITE so the pool stays writable for next checkout."""
    pool, conn = make_pool()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid):
        pass

    sqls = [c.args[0] for c in conn.execute.call_args_list]
    assert "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE" in sqls


# ===========================================================================
# A-M4 (round-2): pool-poisoning prevention -- terminate() on READ WRITE failure
# ===========================================================================


@pytest.mark.asyncio
async def test_readonly_terminates_connection_on_read_write_reset_failure() -> None:
    """If the READ WRITE reset fails, the connection MUST be terminated so
    asyncpg's pool discards it instead of handing the next borrower a
    read-only session that would reject writes with
    ``read_only_sql_transaction``.
    """
    pool, conn = make_pool()
    conn.terminate = MagicMock()
    uid = uuid4()

    async def execute_side_effect(sql: str, *args: Any) -> None:
        if sql == "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE":
            raise RuntimeError("read-write reset blew up")

    conn.execute.side_effect = execute_side_effect

    with pytest.raises(RuntimeError, match="read-write reset blew up"):
        async with user_scoped_connection_readonly(pool, uid):
            pass

    conn.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_readonly_terminates_connection_on_cancelled_error() -> None:
    """A ``CancelledError`` mid-RESET must still trigger terminate() and
    propagate. ``CancelledError`` is a ``BaseException`` (not
    ``Exception``), so this test exercises the wider catch.
    """
    import asyncio

    pool, conn = make_pool()
    conn.terminate = MagicMock()
    uid = uuid4()

    async def execute_side_effect(sql: str, *args: Any) -> None:
        if sql == "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE":
            raise asyncio.CancelledError()

    conn.execute.side_effect = execute_side_effect

    with pytest.raises(asyncio.CancelledError):
        async with user_scoped_connection_readonly(pool, uid):
            pass

    conn.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_readonly_does_not_terminate_on_clean_exit() -> None:
    """No termination on the happy path -- the connection must recycle normally."""
    pool, conn = make_pool()
    conn.terminate = MagicMock()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid):
        pass

    conn.terminate.assert_not_called()


# ===========================================================================
# pool.acquire timeout: forwarding (parity with user_scoped_connection)
# ===========================================================================


@pytest.mark.asyncio
async def test_readonly_default_timeout_forwarded_to_pool_acquire() -> None:
    """The default pool-acquire timeout MUST be forwarded as ``timeout=`` on every acquire."""
    pool, _ = make_pool()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid):
        pass

    pool.acquire.assert_called_once_with(timeout=DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS)


@pytest.mark.asyncio
async def test_readonly_custom_timeout_forwarded_to_pool_acquire() -> None:
    pool, _ = make_pool()
    uid = uuid4()

    async with user_scoped_connection_readonly(pool, uid, pool_acquire_timeout_seconds=2.5):
        pass

    pool.acquire.assert_called_once_with(timeout=2.5)


@pytest.mark.parametrize("bad_value", [0, 0.0, -1, -0.001])
@pytest.mark.asyncio
async def test_readonly_rejects_non_positive_timeout(bad_value: float) -> None:
    pool, _ = make_pool()
    uid = uuid4()

    with pytest.raises(ValueError, match="pool_acquire_timeout_seconds must be positive"):
        async with user_scoped_connection_readonly(
            pool, uid, pool_acquire_timeout_seconds=bad_value
        ):
            pass  # pragma: no cover


@pytest.mark.parametrize("bad_value", [True, False, "5.0", None])
@pytest.mark.asyncio
async def test_readonly_rejects_bad_timeout_type(bad_value: Any) -> None:
    """``bool`` / ``str`` / ``None`` must be rejected with TypeError."""
    pool, _ = make_pool()
    uid = uuid4()

    with pytest.raises(TypeError, match="pool_acquire_timeout_seconds must be float"):
        async with user_scoped_connection_readonly(
            pool, uid, pool_acquire_timeout_seconds=bad_value
        ):
            pass  # pragma: no cover
