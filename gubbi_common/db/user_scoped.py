"""Per-user RLS-scoped database connections for the shared journal schema.

The ``user_scoped_connection`` async context manager acquires a pooled
connection, opens a transaction, and applies two transaction-local
GUCs:

- ``app.current_user_id`` -- the authenticated user UUID, consumed by
  Row-Level Security policies on user-scoped tables (entries, topics,
  conversations, messages, audit_log).
- ``hnsw.ef_search`` -- pgvector HNSW search precision for this
  transaction. Higher = better recall, slower; lower = faster, less
  recall. Default ``DEFAULT_HNSW_EF_SEARCH`` matches typical production
  tuning.

Both consumers (journalctl + journalctl-cloud) wrap every user-facing
DB operation in this context manager so RLS is consistently enforced.

``MissingUserIdError`` is raised when callers attempt to acquire a
scoped connection without an authenticated user (a programming error,
not a runtime data condition). Callers must authenticate first.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    import asyncpg

DEFAULT_HNSW_EF_SEARCH = 100
MIN_HNSW_EF_SEARCH = 1
MAX_HNSW_EF_SEARCH = 1000


class MissingUserIdError(RuntimeError):
    """Raised when a scoped connection is requested without an authenticated user."""


@asynccontextmanager
async def user_scoped_connection(
    pool: asyncpg.Pool,
    user_id: UUID,
    *,
    hnsw_ef_search: int = DEFAULT_HNSW_EF_SEARCH,
) -> AsyncIterator[asyncpg.Connection]:
    try:
        import asyncpg  # noqa: PLC0415,F401
    except ImportError as exc:
        raise ImportError(
            "gubbi_common.db requires asyncpg. Install with: pip install gubbi-common[db]"
        ) from exc
    if user_id is None:
        raise MissingUserIdError("user_scoped_connection requires a user_id -- received None")
    # PEP 563 makes annotations strings at runtime, but isinstance() args are
    # evaluated normally (UUID is a class, not a string annotation here).
    if not isinstance(user_id, UUID):
        raise TypeError(f"user_id must be UUID, got {type(user_id).__name__}")
    ef_search = int(hnsw_ef_search)
    if not (MIN_HNSW_EF_SEARCH <= ef_search <= MAX_HNSW_EF_SEARCH):
        raise ValueError(
            f"hnsw_ef_search must be in [{MIN_HNSW_EF_SEARCH}, {MAX_HNSW_EF_SEARCH}], "
            f"got {hnsw_ef_search}"
        )
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(
            "SELECT set_config('app.current_user_id', $1, true)",
            str(user_id),
        )
        await conn.execute(
            "SELECT set_config('hnsw.ef_search', $1, true)",
            str(ef_search),
        )
        yield conn
