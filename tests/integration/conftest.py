"""Integration test fixtures: real Postgres via testcontainers.

This conftest is loaded only for tests under ``tests/integration/``. The
``pg_pool`` fixture spins a ``pgvector/pgvector:pg16`` container for the
session, applies a minimal ``audit_log`` schema, and yields an
``asyncpg.Pool`` to consumers.

The fast lane is unaffected: every integration test is marked
``@pytest.mark.integration`` and the marker is auto-skipped unless
``INTEGRATION=1`` is set in the environment. This keeps Docker out of
the default ``pytest`` invocation while still letting a release-time CI
job exercise these tests with one extra env var.

Schema vendored here MUST mirror gubbi's Alembic migration 0016 partial
unique index for audit dedup -- update both together. ``MIGRATION_DDL_PATH``
points at the gubbi migration file; tests that compare the vendored DDL
against the upstream string skip if that path is absent (e.g. when the
gubbi-common repo is checked out without the gubbi sibling).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    import asyncpg

# Sibling-repo path to the gubbi alembic versions directory. The audit
# dedup partial-index DDL lives in a file matching ``*0016*.py`` here.
# Tests that cross-check the vendored mini-schema against the live
# migration text use ``MIGRATION_DDL_PATH.exists()`` to skip in
# environments where gubbi is not checked out alongside gubbi-common
# (e.g. CI that runs only this repo). The path layout reflects the
# actual gubbi tree shape: <repo>/gubbi/gubbi/alembic/versions/. If
# gubbi reorganises this path, update here and any test that consults
# the constant.
MIGRATION_DDL_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "gubbi"
    / "gubbi"
    / "alembic"
    / "versions"
)


# Mirror of gubbi/migrations/0016 -- update both together.
# The ``audit_log_content_hash_uidx`` partial unique index is the
# substrate for ``AUDIT_INSERT_DEDUPED_SQL``'s ``ON CONFLICT`` clause.
AUDIT_LOG_DDL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGSERIAL PRIMARY KEY,
    actor_type   TEXT NOT NULL,
    actor_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT,
    target_id    TEXT,
    reason       TEXT,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address   INET,
    user_agent   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS audit_log_content_hash_uidx
    ON audit_log (target_id, action, (metadata->>'content_hash'))
    WHERE metadata ? 'content_hash';
"""


def _integration_enabled() -> bool:
    return os.environ.get("INTEGRATION") == "1"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip every ``@pytest.mark.integration`` test unless INTEGRATION=1."""
    if _integration_enabled():
        return
    skip_marker = pytest.mark.skip(reason="integration tests skipped (set INTEGRATION=1 to run)")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_marker)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def pg_pool() -> AsyncIterator[asyncpg.Pool]:
    """Session-scoped asyncpg pool against a fresh pgvector/pg16 container.

    The container is started once per pytest session and torn down at
    the end. The minimal ``audit_log`` schema (table + partial unique
    index) is applied immediately after the container is reachable.
    """
    if not _integration_enabled():
        pytest.skip("integration tests skipped (set INTEGRATION=1 to run)")

    import asyncpg
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("pgvector/pgvector:pg16") as container:
        dsn = (
            f"postgresql://{container.username}:{container.password}"
            f"@{container.get_container_host_ip()}"
            f":{container.get_exposed_port(5432)}"
            f"/{container.dbname}"
        )
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
        assert pool is not None
        try:
            async with pool.acquire() as conn:
                await conn.execute(AUDIT_LOG_DDL)
            yield pool
        finally:
            await pool.close()
