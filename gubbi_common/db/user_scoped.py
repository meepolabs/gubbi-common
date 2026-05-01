from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    import asyncpg

DEFAULT_HNSW_EF_SEARCH = 100


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
    if not isinstance(user_id, UUID):
        raise TypeError(f"user_id must be UUID, got {type(user_id).__name__}")
    ef_search = int(hnsw_ef_search)
    if not (1 <= ef_search <= 1000):
        raise ValueError(f"hnsw_ef_search must be in [1, 1000], got {hnsw_ef_search}")
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
