"""Per-user RLS-scoped database connections for the shared journal schema.

The ``user_scoped_connection`` async context manager acquires a pooled
connection, opens a transaction, and applies two GUCs:

- ``app.current_user_id`` -- the authenticated user UUID, consumed by
  Row-Level Security policies on user-scoped tables (entries, topics,
  conversations, messages, audit_log).
- ``hnsw.ef_search`` -- pgvector HNSW search precision for this scope.
  Higher = better recall, slower; lower = faster, less recall. Default
  ``DEFAULT_HNSW_EF_SEARCH`` matches typical production tuning.

Both consumers (gubbi + gubbi-cloud) wrap every user-facing DB operation
in this context manager so RLS is consistently enforced.

``user_scoped_connection`` opens a transaction and uses transaction-local
``set_config(..., true)``. ``user_scoped_connection_readonly`` skips the
transaction and uses session-scoped ``set_config(..., false)``; it is
intended for read paths where transaction overhead is unwanted. Both
variants RESET the GUCs in a finally block so the connection returns to
the pool with a pristine session, preventing GUC bleed across checkouts.

``MissingUserIdError`` is raised when callers attempt to acquire a
scoped connection without an authenticated user (a programming error,
not a runtime data condition). Callers must authenticate first.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Final
from uuid import UUID

import asyncpg

logger = logging.getLogger(__name__)

DEFAULT_HNSW_EF_SEARCH = 100
MIN_HNSW_EF_SEARCH = 1
MAX_HNSW_EF_SEARCH = 1000

# Default timeout (in seconds) for ``pool.acquire()``. Without a timeout,
# a slow DB combined with many concurrent requests can exhaust the pool
# and every request hangs forever waiting on a connection. With this
# default, asyncpg raises ``asyncio.TimeoutError`` after N seconds and
# the request returns a clean error rather than piling up. Five seconds
# is generous enough to absorb pool warm-up and brief contention spikes
# (healthy pool acquires are sub-millisecond) while well under typical
# HTTP request budgets, so it only fires on genuine pool exhaustion or
# DB-down conditions -- exactly when callers should fail fast.
DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS = 5.0

# GUCs that user_scoped_connection / user_scoped_connection_readonly are
# allowed to ``RESET``. Two members today: ``app.current_user_id`` (RLS
# scope) and ``hnsw.ef_search`` (pgvector recall knob). The allowlist is
# enforced at ``__safe_reset`` entry; passing any other name is a
# programming error and raises ``ValueError`` so the bug is caught
# locally rather than silently escaping into a RESET command. We avoid
# ``assert`` here because ``assert`` is stripped under ``python -O``.
_GUC_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "app.current_user_id",
        "hnsw.ef_search",
    }
)

__all__ = [
    "DEFAULT_HNSW_EF_SEARCH",
    "DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS",
    "MAX_HNSW_EF_SEARCH",
    "MIN_HNSW_EF_SEARCH",
    "MissingUserIdError",
    "user_scoped_connection",
    "user_scoped_connection_readonly",
]


class MissingUserIdError(RuntimeError):
    """Raised when a scoped connection is requested without an authenticated user."""


def _validate_inputs(
    user_id: UUID | None,
    hnsw_ef_search: int,
    pool_acquire_timeout_seconds: float,
) -> tuple[int, float]:
    if user_id is None:
        raise MissingUserIdError("user_scoped_connection requires a user_id -- received None")
    if not isinstance(user_id, UUID):
        raise TypeError(f"user_id must be UUID, got {type(user_id).__name__}")
    # ``bool`` is a subclass of ``int``; reject it explicitly so
    # ``hnsw_ef_search=True`` does not silently coerce to 1.
    if isinstance(hnsw_ef_search, bool) or not isinstance(hnsw_ef_search, int):
        raise TypeError(f"hnsw_ef_search must be int, got {type(hnsw_ef_search).__name__}")
    if not (MIN_HNSW_EF_SEARCH <= hnsw_ef_search <= MAX_HNSW_EF_SEARCH):
        raise ValueError(
            f"hnsw_ef_search must be in [{MIN_HNSW_EF_SEARCH}, {MAX_HNSW_EF_SEARCH}], "
            f"got {hnsw_ef_search}"
        )
    # Mirror the bool guard above: ``True`` / ``False`` are ``int``
    # subclasses and would silently coerce to 1.0 / 0.0 timeouts. Reject
    # both explicitly. Allow ``int`` and ``float`` since either is a
    # natural way to spell "5 seconds".
    if isinstance(pool_acquire_timeout_seconds, bool) or not isinstance(
        pool_acquire_timeout_seconds, int | float
    ):
        raise TypeError(
            "pool_acquire_timeout_seconds must be float, got "
            f"{type(pool_acquire_timeout_seconds).__name__}"
        )
    if pool_acquire_timeout_seconds <= 0:
        raise ValueError(
            "pool_acquire_timeout_seconds must be positive, " f"got {pool_acquire_timeout_seconds}"
        )
    return hnsw_ef_search, float(pool_acquire_timeout_seconds)


async def _set_ef_search(conn: asyncpg.Connection, ef_search: int, *, local: bool) -> None:
    """Apply the ``hnsw.ef_search`` GUC, tolerating the missing-extension case.

    pgvector defines the ``hnsw.ef_search`` parameter; a Postgres without
    pgvector raises ``UndefinedObjectError``. The helper is required for
    RLS correctness but pgvector is optional for non-vector queries, so
    we log a warning and continue rather than fail the request.
    """
    sql = (
        "SELECT set_config('hnsw.ef_search', $1, true)"
        if local
        else "SELECT set_config('hnsw.ef_search', $1, false)"
    )
    try:
        await conn.execute(sql, str(ef_search))
    except asyncpg.exceptions.UndefinedObjectError as exc:
        logger.warning(
            "hnsw.ef_search GUC unavailable (pgvector not loaded?); continuing without it: %s",
            exc,
        )


async def __safe_reset(conn: asyncpg.Connection, guc: str) -> None:
    """RESET *guc*; log and swallow errors so cleanup never masks the caller's exception.

    *guc* MUST be a member of :data:`_GUC_ALLOWLIST`. Passing any other
    name is a programming error and raises ``ValueError`` so the bug is
    caught locally rather than silently escaping into a RESET command.
    Production callers only pass the two known GUCs
    (``app.current_user_id`` and ``hnsw.ef_search``). The allowlist
    closes the surface that would otherwise let a future caller smuggle
    arbitrary text into a ``RESET`` statement. We raise (rather than
    ``assert``) because ``assert`` is stripped under ``python -O`` and
    would silently remove this guard in optimised builds.

    Each RESET runs in its own try/except: a failure to reset
    ``app.current_user_id`` must not prevent us from attempting to reset
    ``hnsw.ef_search`` (or vice versa).
    """
    if guc not in _GUC_ALLOWLIST:
        raise ValueError(f"GUC {guc!r} not in _GUC_ALLOWLIST; safe-reset refused")
    try:
        await conn.execute(f"RESET {guc}")
    except Exception as exc:  # noqa: BLE001 -- defensive cleanup must never mask
        logger.warning("RESET %s failed during scoped-connection exit: %s", guc, exc)


@asynccontextmanager
async def user_scoped_connection(
    pool: asyncpg.Pool,
    user_id: UUID,
    *,
    hnsw_ef_search: int = DEFAULT_HNSW_EF_SEARCH,
    pool_acquire_timeout_seconds: float = DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS,
) -> AsyncIterator[asyncpg.Connection]:
    """Acquire a pooled connection inside a transaction with RLS GUCs applied.

    Uses transaction-local ``set_config(..., true)`` so the GUCs are
    scoped to the open transaction. The finally block additionally runs
    ``RESET`` on each GUC; while transaction-local config is dropped on
    transaction end, the explicit RESET defends against future code that
    might switch the prologue to session scope or extend the connection
    lifetime past the transaction.

    ``pool_acquire_timeout_seconds`` bounds the wait for a connection
    from the pool. Without it, a slow DB plus piling concurrent requests
    would hang every caller indefinitely; with it, asyncpg raises
    ``asyncio.TimeoutError`` when no connection is available within the
    budget. Defaults to ``DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS``.
    """
    ef_search, acquire_timeout = _validate_inputs(
        user_id, hnsw_ef_search, pool_acquire_timeout_seconds
    )
    async with pool.acquire(timeout=acquire_timeout) as conn, conn.transaction():
        try:
            await conn.execute(
                "SELECT set_config('app.current_user_id', $1, true)",
                str(user_id),
            )
            await _set_ef_search(conn, ef_search, local=True)
            yield conn
        finally:
            await __safe_reset(conn, "app.current_user_id")
            await __safe_reset(conn, "hnsw.ef_search")


@asynccontextmanager
async def user_scoped_connection_readonly(
    pool: asyncpg.Pool,
    user_id: UUID,
    *,
    hnsw_ef_search: int = DEFAULT_HNSW_EF_SEARCH,
    pool_acquire_timeout_seconds: float = DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS,
) -> AsyncIterator[asyncpg.Connection]:
    """Read-only scoped connection. Do NOT call audit-writing code inside this context.

    Skips an explicit transaction and uses session-scoped
    ``set_config(..., false)`` so the GUCs persist across statements
    within the connection. Before the GUC prologue we run
    ``SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`` -- this is
    the session-scope equivalent of ``SET TRANSACTION READ ONLY`` and is
    the only form that holds across asyncpg's autocommit-shaped ``execute``
    calls. A subsequent ``INSERT`` / ``UPDATE`` / ``DELETE`` issued on the
    connection will then be rejected by Postgres with
    ``read_only_sql_transaction``, making this an enforcement boundary
    rather than a docstring promise. The accompanying RESET cycle in the
    finally block clears the read-only flag so the next pool checkout
    inherits a writable session.

    The finally block runs ``RESET`` on each GUC -- this is load-bearing,
    not defensive: without it the next caller to check this connection
    out of the pool would inherit the previous user's RLS scope.

    ``pool_acquire_timeout_seconds`` bounds the wait for a connection
    from the pool; see ``user_scoped_connection`` for rationale.
    Defaults to ``DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS``.
    """
    ef_search, acquire_timeout = _validate_inputs(
        user_id, hnsw_ef_search, pool_acquire_timeout_seconds
    )
    async with pool.acquire(timeout=acquire_timeout) as conn:
        try:
            await conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            await conn.execute(
                "SELECT set_config('app.current_user_id', $1, false)",
                str(user_id),
            )
            await _set_ef_search(conn, ef_search, local=False)
            yield conn
        finally:
            await __safe_reset(conn, "app.current_user_id")
            await __safe_reset(conn, "hnsw.ef_search")
            # Drop the read-only flag so the next pool checkout starts
            # writable. We catch ``BaseException`` here (not just
            # ``Exception``) so an ``asyncio.CancelledError`` arriving
            # mid-RESET cannot leave the connection stuck in read-only
            # state when asyncpg recycles it back to the pool. On any
            # failure we ``conn.terminate()`` -- asyncpg's synchronous
            # force-close that aborts the connection without sending a
            # graceful Terminate. The pool detects the closed connection
            # on next acquire and opens a replacement, instead of handing
            # the next borrower a session that rejects writes with
            # ``read_only_sql_transaction``. The original error is
            # re-raised so cancellation / failure still propagates.
            try:
                await conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE")
            except BaseException as exc:  # noqa: BLE001 -- includes CancelledError on purpose
                logger.warning(
                    "RESET TRANSACTION READ WRITE failed; terminating connection to "
                    "prevent pool poisoning: error=%s error_type=%s",
                    exc,
                    type(exc).__name__,
                )
                # Force asyncpg to discard the connection rather than
                # recycle in read-only state.
                conn.terminate()
                raise
