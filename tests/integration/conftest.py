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
its current head (mig 0020 adds ``target_kind`` and rebuilds the partial
unique index for audit dedup; mig 0029 adds the
``audit_log_target_kind_invariant`` CHECK constraint enforcing
``target_id IS NULL OR target_kind IS NOT NULL``; mig 0031 prepends
``actor_id`` to the dedup index to close the cross-actor false-collision
tampering vector; mig 0003 of the post-squash chain adds the app role's
five-column SELECT grant plus the self-only SELECT policy the deduped
INSERT's ON CONFLICT inference needs) -- update both together.
``MIGRATION_DDL_PATH`` is resolved by
:mod:`tests.integration.sibling_repo`, which finds gubbi independently of
Git-worktree nesting; tests that compare the vendored DDL against the
upstream source skip when it is absent, unless
``REQUIRE_GUBBI_MIGRATIONS=1`` (the CI integration lane) makes absence a
failure.
"""

from __future__ import annotations

import os
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
import pytest_asyncio

from tests.integration.sibling_repo import resolve_gubbi_versions_dir, sibling_required

if TYPE_CHECKING:
    import asyncpg

# Sibling-repo path to the gubbi alembic versions directory, or the
# conventional main-checkout location when gubbi is not present (so
# ``.exists()`` stays False and the skip path still reads naturally).
# Resolution is delegated so worktree nesting cannot silently turn the
# drift guard into a skip -- see ``tests/integration/sibling_repo.py``.
# The ``AUDIT_LOG_DDL_BASED_ON`` constant below pins the high-water mark
# of audit_log migrations reflected in the vendored DDL.
_RESOLVED_VERSIONS_DIR = resolve_gubbi_versions_dir()
MIGRATION_DDL_PATH: Final[Path] = (
    _RESOLVED_VERSIONS_DIR
    if _RESOLVED_VERSIONS_DIR is not None
    else Path(__file__).resolve().parents[2].parent / "gubbi" / "gubbi" / "alembic" / "versions"
)


def require_migration_source(context: str) -> None:
    """Skip, or fail when the sibling checkout is mandatory, if gubbi is absent.

    ``REQUIRE_GUBBI_MIGRATIONS=1`` is set by the CI integration lane
    after it checks out the pinned gubbi revision. There, a missing
    migration source means the checkout step regressed, and skipping
    would turn a broken lane green.
    """
    if MIGRATION_DDL_PATH.exists():
        return
    message = (
        f"{context}: gubbi migration source not found at {MIGRATION_DDL_PATH}. "
        "Check out gubbi alongside gubbi-common, or unset "
        "REQUIRE_GUBBI_MIGRATIONS for a standalone run."
    )
    if sibling_required():
        raise AssertionError(message)
    pytest.skip(message)


# Mirror of gubbi/migrations through 0031 -- update both together.
# Migration 0020 added the ``target_kind`` column and rebuilt the
# ``audit_log_content_hash_uidx`` partial unique index with
# ``target_kind`` as the leading column.  Migration 0031 prepends
# ``actor_id`` to that 4-tuple to close the cross-actor false-collision
# tampering vector (two actors with the same content_hash would have
# collided pre-0031, silently dropping the second row under the
# ``ON CONFLICT DO NOTHING`` path that cloud-api uses for webhook
# idempotency). The 5-column partial unique index is the substrate for
# ``AUDIT_INSERT_DEDUPED_SQL``'s ``ON CONFLICT`` clause. Migration 0021
# swaps a perf index (not reflected here; the DDL pulls in only what
# the dedup/drift tests need). Migration 0022 converts ``id`` from
# BIGSERIAL to GENERATED ALWAYS AS IDENTITY. Migration 0028 adds the
# ``actor_id <> target_id`` self-attribution guard (CHECK constraint
# -- not reflected here; gubbi-common tests do not insert rows that
# would trip it). Migration 0029 adds the
# ``audit_log_target_kind_invariant`` CHECK constraint enforcing
# ``target_id IS NULL OR target_kind IS NOT NULL`` -- the DB-level
# belt-and-braces guard for the same invariant the Python boundary
# enforces in ``record_audit_async``.  We use ``ADD CONSTRAINT IF NOT
# EXISTS ... NOT VALID`` followed by ``VALIDATE CONSTRAINT`` to mirror
# the migration shape so the probe-side check (``convalidated = true``)
# fires identically against this vendored schema as it does against a
# real Alembic upgrade.
#
# The trailing capability block mirrors the audit_log surface at the
# chain's current head: the frozen squash baseline's ``journal_app``
# INSERT grant, self-only INSERT policy and row-level security, plus
# migration ``0003``'s two halves -- a five-column SELECT grant
# (``actor_id, target_kind, target_id, action, metadata``) and the
# ``audit_log_app_select_self_only`` policy whose USING predicate
# mirrors the INSERT policy's WITH CHECK predicate exactly. Both halves
# are required: the deduped INSERT's ON CONFLICT inference reads those
# five columns, and the column grant alone still trips row-level
# security while the policy alone still trips the column ACL. Table-wide
# SELECT stays denied, so ``actor_type``, ``occurred_at``, ``reason``,
# ``ip_address`` and ``user_agent`` remain unreadable through the app
# role. This is an integration fixture, not production DDL -- gubbi's
# Alembic chain remains the schema owner.
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
    ON audit_log (actor_id, target_kind, target_id, action, (metadata->>'content_hash'))
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

-- The app role the grants and policies below are written for. Created
-- here because the container starts with only its own superuser; in a
-- real deployment the roles pre-date the baseline migration.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'journal_app') THEN
        CREATE ROLE journal_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
-- FORCE, so the policies also constrain the table owner. Without it a
-- test running as owner bypasses row-level security entirely and the
-- self-only predicates are unenforced for exactly the connection the
-- fixture uses.
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

GRANT INSERT ON TABLE audit_log TO journal_app;

DROP POLICY IF EXISTS audit_log_app_insert_self_only ON audit_log;
CREATE POLICY audit_log_app_insert_self_only ON audit_log
    FOR INSERT TO journal_app
    WITH CHECK (
        actor_id = (SELECT NULLIF(current_setting('app.current_user_id', true), ''))
        AND actor_id <> ''
        AND actor_type = 'user'
    );

-- Migration 0003, half one: column-level SELECT on exactly the five
-- columns the deduped INSERT's ON CONFLICT inference reads. Never
-- table-wide.
GRANT SELECT (actor_id, target_kind, target_id, action, metadata)
    ON TABLE audit_log TO journal_app;

-- Migration 0003, half two: the self-only SELECT policy. Its USING
-- predicate mirrors the INSERT policy's WITH CHECK predicate, so an
-- author reads exactly the rows it may write.
DROP POLICY IF EXISTS audit_log_app_select_self_only ON audit_log;
CREATE POLICY audit_log_app_select_self_only ON audit_log
    FOR SELECT TO journal_app
    USING (
        actor_id = (SELECT NULLIF(current_setting('app.current_user_id', true), ''))
        AND actor_id <> ''
        AND actor_type = 'user'
    );
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
AUDIT_LOG_DDL_BASED_ON: Final[str] = "20260914_0003"

# The exact set of columns migration 0003 grants ``journal_app`` SELECT
# on -- the conflict-target columns of ``audit_log_content_hash_uidx``
# plus ``metadata``. Broadening this set is the over-broadening the
# capability probe rejects, so the fixture-contract test asserts equality,
# not containment.
AUDIT_LOG_APP_SELECT_COLUMNS: Final[frozenset[str]] = frozenset(
    {
        "actor_id",
        "target_kind",
        "target_id",
        "action",
        "metadata",
    }
)

# Name of the self-only SELECT policy migration 0003 adds, and of the
# baseline INSERT policy whose predicate it mirrors.
AUDIT_LOG_APP_SELECT_POLICY: Final[str] = "audit_log_app_select_self_only"
AUDIT_LOG_APP_INSERT_POLICY: Final[str] = "audit_log_app_insert_self_only"
AUDIT_LOG_APP_ROLE: Final[str] = "journal_app"

# Columns the app role must NOT be able to read. Asserted individually as
# well as via the equality check above, so a widening that adds a column
# names the column in the failure.
AUDIT_LOG_APP_DENIED_COLUMNS: Final[tuple[str, ...]] = (
    "id",
    "actor_type",
    "target_type",
    "reason",
    "occurred_at",
    "ip_address",
    "user_agent",
)

# The self-only predicate, as the contract rather than as whatever the
# fixture happens to emit: actor id equals the request-scoped setting, is
# non-empty, and the row is user-attributed. BOTH the SELECT USING and
# INSERT WITH CHECK predicates are compared against this, independently --
# comparing them only to each other passes when both are widened to
# ``true`` together.
AUDIT_LOG_SELF_ONLY_PREDICATE: Final[str] = (
    "((actor_id = (SELECT NULLIF(current_setting('app.current_user_id'::text, true), "
    "''::text) AS \"nullif\")) AND (actor_id <> ''::text) AND (actor_type = 'user'::text))"
)

_WHITESPACE_RE = re.compile(r"\s+")


def normalize_predicate(predicate: str | None) -> str | None:
    """Collapse whitespace in a ``pg_policies`` predicate for comparison.

    PostgreSQL re-renders predicates from the parse tree, so indentation
    and line breaks are not stable enough to compare literally, while the
    token sequence is.
    """
    if predicate is None:
        return None
    return _WHITESPACE_RE.sub(" ", predicate).replace("( ", "(").replace(" )", ")").strip()


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
