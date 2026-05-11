"""Tests for gubbi_common.db.user_scoped."""

from __future__ import annotations

import asyncio
import logging
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

        # Prologue (2 set_config) + cleanup (2 RESET) = 4 execute calls.
        assert conn.execute.call_count == 4
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

        # 2 set_config (prologue, before raise) + 2 RESET (finally cleanup).
        assert conn.execute.await_count == 4
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

        # Verify conn1 got uid1 (prologue + RESET cleanup = 4 execute calls)
        assert conn1.execute.await_count == 4
        conn1_first_call = conn1.execute.call_args_list[0]
        assert conn1_first_call == call(
            "SELECT set_config('app.current_user_id', $1, true)",
            str(uid1),
        )

        # Verify conn2 got uid2
        assert conn2.execute.await_count == 4
        conn2_first_call = conn2.execute.call_args_list[0]
        assert conn2_first_call == call(
            "SELECT set_config('app.current_user_id', $1, true)",
            str(uid2),
        )


# ===========================================================================
# H-16.1 / .2 / .3 / .4: RESET-on-exit + ef_search guard + strict int
# ===========================================================================


class TestRESETOnExit:
    @pytest.mark.asyncio
    async def test_resets_user_id_guc_on_exit(self) -> None:
        pool, conn = make_pool()
        uid = uuid4()

        async with user_scoped_connection(pool, uid):
            pass

        executed = [c.args[0] for c in conn.execute.call_args_list]
        assert "RESET app.current_user_id" in executed

    @pytest.mark.asyncio
    async def test_resets_ef_search_guc_on_exit(self) -> None:
        pool, conn = make_pool()
        uid = uuid4()

        async with user_scoped_connection(pool, uid):
            pass

        executed = [c.args[0] for c in conn.execute.call_args_list]
        assert "RESET hnsw.ef_search" in executed

    @pytest.mark.asyncio
    async def test_resets_run_even_on_exception(self) -> None:
        pool, conn = make_pool()
        uid = uuid4()

        with pytest.raises(RuntimeError, match="boom"):
            async with user_scoped_connection(pool, uid):
                raise RuntimeError("boom")

        executed = [c.args[0] for c in conn.execute.call_args_list]
        assert "RESET app.current_user_id" in executed
        assert "RESET hnsw.ef_search" in executed

    @pytest.mark.asyncio
    async def test_reset_failure_does_not_mask_original_error(self) -> None:
        """Original exception must propagate even if RESET inside finally fails."""
        pool, conn = make_pool()
        uid = uuid4()

        async def execute_side_effect(sql: str, *args: Any) -> None:
            if sql.startswith("RESET"):
                raise RuntimeError("reset blew up")

        conn.execute.side_effect = execute_side_effect

        with pytest.raises(RuntimeError, match="original"):
            async with user_scoped_connection(pool, uid):
                raise RuntimeError("original")


class TestEfSearchUndefinedGuard:
    @pytest.mark.asyncio
    async def test_ef_search_undefined_object_logs_and_continues(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When pgvector is not installed, set_config('hnsw.ef_search', ...)
        raises UndefinedObjectError; helper logs a warning and proceeds."""
        import asyncpg as real_asyncpg

        pool, conn = make_pool()
        uid = uuid4()

        async def execute_side_effect(sql: str, *args: Any) -> None:
            if "hnsw.ef_search" in sql and "set_config" in sql:
                raise real_asyncpg.exceptions.UndefinedObjectError(
                    'unrecognized configuration parameter "hnsw.ef_search"'
                )

        conn.execute.side_effect = execute_side_effect

        with caplog.at_level(logging.WARNING, logger="gubbi_common.db.user_scoped"):
            async with user_scoped_connection(pool, uid):
                pass

        warnings = [r for r in caplog.records if "hnsw.ef_search" in r.message]
        assert warnings, "expected a warning log for missing pgvector ef_search"


class TestStrictIntCheck:
    @pytest.mark.parametrize("bad_value", [True, False])
    @pytest.mark.asyncio
    async def test_strict_int_rejects_bool(self, bad_value: bool) -> None:
        """``int(True)`` is ``1`` -- a bool must NOT silently coerce."""
        pool, _ = make_pool()
        uid = uuid4()

        with pytest.raises(TypeError, match="hnsw_ef_search must be int"):
            async with user_scoped_connection(pool, uid, hnsw_ef_search=bad_value):  # type: ignore[arg-type]
                pass  # pragma: no cover

    @pytest.mark.parametrize("bad_value", ["100", 1.5, 100.0])
    @pytest.mark.asyncio
    async def test_strict_int_rejects_str_float(self, bad_value: Any) -> None:
        pool, _ = make_pool()
        uid = uuid4()

        with pytest.raises(TypeError, match="hnsw_ef_search must be int"):
            async with user_scoped_connection(pool, uid, hnsw_ef_search=bad_value):
                pass  # pragma: no cover


# ===========================================================================
# A-H4: __safe_reset GUC allowlist
# ===========================================================================


class TestSafeResetAllowlist:
    @pytest.mark.asyncio
    async def test_safe_reset_rejects_non_allowlisted_guc(self) -> None:
        """A-H4: __safe_reset must raise ValueError on a GUC outside the allowlist.

        The allowlist closes the surface that would let a future caller pass
        arbitrary text into a RESET statement. We use an explicit raise
        (not ``assert``) so the guard survives ``python -O``.
        """
        from gubbi_common.db import user_scoped as us

        conn = MagicMock()
        conn.execute = AsyncMock()
        with pytest.raises(ValueError, match="not in _GUC_ALLOWLIST"):
            # ``__safe_reset`` is name-mangled at class scope but free at module
            # scope; access via attribute lookup to dodge any local mangling.
            await getattr(us, "_user_scoped__safe_reset", us.__dict__["__safe_reset"])(
                conn, "evil; DROP TABLE users"
            )
        # And RESET was not issued.
        conn.execute.assert_not_called()

    @pytest.mark.parametrize("guc", ["app.current_user_id", "hnsw.ef_search"])
    @pytest.mark.asyncio
    async def test_safe_reset_accepts_known_gucs(self, guc: str) -> None:
        from gubbi_common.db import user_scoped as us

        conn = MagicMock()
        conn.execute = AsyncMock()
        await us.__dict__["__safe_reset"](conn, guc)
        conn.execute.assert_awaited_once_with(f"RESET {guc}")

    def test_guc_allowlist_membership(self) -> None:
        from gubbi_common.db.user_scoped import _GUC_ALLOWLIST

        assert frozenset({"app.current_user_id", "hnsw.ef_search"}) == _GUC_ALLOWLIST
