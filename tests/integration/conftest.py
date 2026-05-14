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

Schema vendored here MUST mirror gubbi's Alembic migration chain through
0029 (mig 0020 adds ``target_kind`` and rebuilds the partial unique
index for audit dedup; mig 0029 adds the
``audit_log_target_kind_invariant`` CHECK constraint enforcing
``target_id IS NULL OR target_kind IS NOT NULL``) -- update both
together. ``MIGRATION_DDL_PATH`` points at the gubbi migrations
directory; tests that compare the vendored DDL against the upstream
string skip if that path is absent (e.g. when the gubbi-common repo is
checked out without the gubbi sibling).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    import asyncpg

# Sibling-repo path to the gubbi alembic versions directory. Tests that
# cross-check the vendored mini-schema against the live migration text
# use ``MIGRATION_DDL_PATH.exists()`` to skip in environments where
# gubbi is not checked out alongside gubbi-common (e.g. CI that runs
# only this repo). Today the dedup partial-index DDL contract lives
# in migration ``20260502_0020_audit_log_target_kind.py``; the
# ``AUDIT_LOG_DDL_BASED_ON`` constant below pins the high-water mark
# of audit_log migrations reflected in the vendored DDL. The path
# layout reflects the actual gubbi tree shape:
# ``<repo>/gubbi/gubbi/alembic/versions/``. If gubbi reorganises this
# path, update here and any test that consults the constant.
MIGRATION_DDL_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "gubbi"
    / "gubbi"
    / "alembic"
    / "versions"
)


# Mirror of gubbi/migrations through 0029 -- update both together.
# Migration 0020 added the ``target_kind`` column and rebuilt the
# ``audit_log_content_hash_uidx`` partial unique index with
# ``target_kind`` as the leading column.  That partial unique index is
# the substrate for ``AUDIT_INSERT_DEDUPED_SQL``'s ``ON CONFLICT``
# clause. Migration 0021 swaps a perf index (not reflected here; the
# DDL pulls in only what the dedup/drift tests need). Migration 0022
# converts ``id`` from BIGSERIAL to GENERATED ALWAYS AS IDENTITY.
# Migration 0028 adds the ``actor_id <> target_id`` self-attribution
# guard (CHECK constraint -- not reflected here; gubbi-common tests do
# not insert rows that would trip it). Migration 0029 adds the
# ``audit_log_target_kind_invariant`` CHECK constraint enforcing
# ``target_id IS NULL OR target_kind IS NOT NULL`` -- the DB-level
# belt-and-braces guard for the same invariant the Python boundary
# enforces in ``record_audit_async``.  We use ``ADD CONSTRAINT IF NOT
# EXISTS ... NOT VALID`` followed by ``VALIDATE CONSTRAINT`` to mirror
# the migration shape so the probe-side check (``convalidated = true``)
# fires identically against this vendored schema as it does against a
# real Alembic upgrade.
AUDIT_LOG_DDL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_type   TEXT NOT NULL,
    actor_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT,
    target_id    TEXT,
    target_kind  TEXT,
    reason       TEXT,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address   INET,
    user_agent   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS audit_log_content_hash_uidx
    ON audit_log (target_kind, target_id, action, (metadata->>'content_hash'))
    WHERE metadata ? 'content_hash';

-- Migration 0029: target_id requires target_kind invariant. PG has no
-- ``ALTER TABLE ... ADD CONSTRAINT IF NOT EXISTS`` for CHECK
-- constraints, so we guard with a DO block to keep the vendored DDL
-- idempotent across container reuses. ``VALIDATE CONSTRAINT`` is
-- unconditional inside the block so ``convalidated`` is true for any
-- probe-side check that filters on it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_namespace n ON n.oid = c.connamespace
        WHERE c.conname = 'audit_log_target_kind_invariant'
          AND n.nspname = current_schema()
    ) THEN
        ALTER TABLE audit_log
            ADD CONSTRAINT audit_log_target_kind_invariant
            CHECK (target_id IS NULL OR target_kind IS NOT NULL) NOT VALID;
        ALTER TABLE audit_log VALIDATE CONSTRAINT audit_log_target_kind_invariant;
    END IF;
END
$$;
"""


# High-water mark of the gubbi ``*audit_log*.py`` Alembic revisions
# reflected in ``AUDIT_LOG_DDL`` above. Update this constant in lockstep
# with any change to ``AUDIT_LOG_DDL``. The drift-guard test
# ``test_audit_ddl_based_on_matches_latest_migration`` glob-scans the
# gubbi sibling repo for ``*audit_log*.py`` migration filenames, parses
# the ``YYYYMMDD_NNNN`` prefix from each, computes the max, and asserts
# it is <= this string. A newer migration than the based-on guard means
# ``AUDIT_LOG_DDL`` is stale and dedup tests are exercising a
# pre-migration shape.
AUDIT_LOG_DDL_BASED_ON: Final[str] = "20260513_0029"


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
