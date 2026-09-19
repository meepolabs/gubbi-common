"""Integration tests guarding against ``audit_log`` schema drift.

Each ``AUDIT_INSERT_*`` SQL constant in ``gubbi_common.audit.sql``
hard-codes a column list. If the table evolves (column added, NOT NULL
flipped on, default removed) and the constant is not updated, INSERTs
silently break in production. These tests parse the column list from
each constant, query ``information_schema.columns`` for the live table,
and assert every NOT-NULL column without a default is present in the
INSERT.

NULL-able columns and columns with a default value are allowed to be
omitted -- those are the cases where the database fills in the value
itself. Columns the INSERT supplies that do not exist in the table also
fail the test; the INSERT would error at execute time.
"""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Final

import pytest

from gubbi_common.audit.sql import (
    AUDIT_INSERT_DEDUPED_SQL,
    AUDIT_INSERT_SQL,
)
from tests.integration.conftest import (
    AUDIT_LOG_APP_DENIED_COLUMNS,
    AUDIT_LOG_APP_INSERT_POLICY,
    AUDIT_LOG_APP_ROLE,
    AUDIT_LOG_APP_SELECT_COLUMNS,
    AUDIT_LOG_APP_SELECT_POLICY,
    AUDIT_LOG_SELF_ONLY_PREDICATE,
    normalize_predicate,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    import asyncpg


pytestmark = pytest.mark.integration


# Match the parenthesised column list in ``INSERT INTO audit_log (col, col, ...)``.
_COLS_RE = re.compile(
    r"INSERT\s+INTO\s+audit_log\s*\((?P<cols>[^)]+)\)",
    re.IGNORECASE | re.DOTALL,
)


def _parse_inserted_columns(sql: str) -> set[str]:
    match = _COLS_RE.search(sql)
    assert match is not None, f"could not parse audit_log column list from SQL:\n{sql}"
    raw = match.group("cols")
    return {col.strip() for col in raw.split(",") if col.strip()}


async def _fetch_required_columns(conn: asyncpg.Connection) -> set[str]:
    """Return columns that are NOT NULL and have no default -- the INSERT must supply them.

    ``GENERATED ALWAYS AS IDENTITY`` columns report ``column_default``
    NULL but the database generates the value itself; treat them as
    "not required" the same way we treat columns with a literal
    DEFAULT.
    """
    rows = await conn.fetch(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'audit_log'
          AND is_nullable = 'NO'
          AND column_default IS NULL
          AND is_identity = 'NO'
        """
    )
    return {row["column_name"] for row in rows}


async def _fetch_all_columns(conn: asyncpg.Connection) -> set[str]:
    rows = await conn.fetch(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'audit_log'
        """
    )
    return {row["column_name"] for row in rows}


async def _assert_insert_covers_required(conn: asyncpg.Connection, sql: str) -> None:
    inserted = _parse_inserted_columns(sql)
    required = await _fetch_required_columns(conn)
    all_cols = await _fetch_all_columns(conn)

    missing = required - inserted
    assert not missing, (
        f"INSERT does not supply NOT-NULL columns {sorted(missing)}; "
        f"audit_log has drifted from the SQL constant"
    )

    unknown = inserted - all_cols
    assert not unknown, (
        f"INSERT references columns {sorted(unknown)} not present in audit_log; "
        f"the INSERT would fail at execute time"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_audit_insert_sql_covers_all_audit_log_columns(pg_pool: asyncpg.Pool) -> None:
    async with pg_pool.acquire() as conn:
        await _assert_insert_covers_required(conn, AUDIT_INSERT_SQL)


@pytest.mark.asyncio(loop_scope="session")
async def test_audit_insert_deduped_sql_covers_required_columns(pg_pool: asyncpg.Pool) -> None:
    async with pg_pool.acquire() as conn:
        await _assert_insert_covers_required(conn, AUDIT_INSERT_DEDUPED_SQL)


# ---------------------------------------------------------------------------
# Partial-unique-index column composition drift guard (mig 0020 + 0031).
# ---------------------------------------------------------------------------
# The ``audit_log_content_hash_uidx`` partial unique index is the
# substrate for ``AUDIT_INSERT_DEDUPED_SQL``'s ON CONFLICT clause. Its
# column composition is keyed on
# ``(actor_id, target_kind, target_id, action,
# metadata->>'content_hash')`` with the partial predicate
# ``WHERE metadata ? 'content_hash'``. Migration 0020 added
# ``target_kind`` as the leading column; migration 0031 prepended
# ``actor_id`` to close a cross-actor false-collision tampering vector.
# A future migration that rebuilds this index with a different column
# order or predicate would silently break dedup at write time (42P10)
# without this test firing.
_EXPECTED_INDEX_COL_TUPLE: tuple[str, str, str, str, str] = (
    "actor_id",
    "target_kind",
    "target_id",
    "action",
    "metadata ->> 'content_hash'",
)


@pytest.mark.asyncio(loop_scope="session")
async def test_dedup_unique_index_column_composition(pg_pool: asyncpg.Pool) -> None:
    """Pin the 5-tuple of columns / expressions on ``audit_log_content_hash_uidx``.

    Walks ``pg_index.indkey`` and resolves attnums via ``pg_attribute``;
    indexed expressions (attnum=0) are rendered via
    ``pg_get_indexdef(indexrelid, position, true)``. The last element of
    the 5-tuple is an expression (``metadata->>'content_hash'``);
    asserted via substring match because the renderer's exact whitespace
    is not stable across PG versions. The partial predicate is asserted
    via ``pg_get_expr(indpred, indrelid)`` substring on
    ``metadata ? 'content_hash'``.
    """
    async with pg_pool.acquire() as conn:
        # Pull the ordered (attnum, position) pairs from pg_index.
        rows = await conn.fetch(
            """
            SELECT
                a.position,
                i.indkey[a.position - 1] AS attnum,
                CASE
                    WHEN i.indkey[a.position - 1] = 0
                        THEN pg_get_indexdef(i.indexrelid, a.position::int, true)
                    ELSE (
                        SELECT attname
                        FROM pg_attribute
                        WHERE attrelid = i.indrelid
                          AND attnum = i.indkey[a.position - 1]
                    )
                END AS rendered
            FROM pg_index i,
                 generate_series(1, array_length(i.indkey, 1)) AS a(position)
            WHERE i.indexrelid = 'audit_log_content_hash_uidx'::regclass
            ORDER BY a.position
            """
        )
        rendered = [row["rendered"] for row in rows]
        assert len(rendered) == 5, (
            f"audit_log_content_hash_uidx has {len(rendered)} columns, expected 5: {rendered}"
        )

        # First four are plain columns -- exact match.
        assert rendered[0] == _EXPECTED_INDEX_COL_TUPLE[0]
        assert rendered[1] == _EXPECTED_INDEX_COL_TUPLE[1]
        assert rendered[2] == _EXPECTED_INDEX_COL_TUPLE[2]
        assert rendered[3] == _EXPECTED_INDEX_COL_TUPLE[3]

        # Fifth is the metadata->>'content_hash' expression; substring
        # match because PG renderer whitespace is not stable.
        assert "metadata" in rendered[4]
        assert "content_hash" in rendered[4]

        # Partial predicate must still be ``metadata ? 'content_hash'``.
        predicate = await conn.fetchval(
            """
            SELECT pg_get_expr(indpred, indrelid)
            FROM pg_index
            WHERE indexrelid = 'audit_log_content_hash_uidx'::regclass
            """
        )
        assert predicate is not None, "audit_log_content_hash_uidx is no longer a partial index"
        assert "content_hash" in predicate, (
            f"partial predicate dropped 'content_hash' reference: {predicate!r}"
        )
        # The jsonb key-exists operator ``?`` is the contract; a swap to
        # e.g. ``metadata->>'content_hash' IS NOT NULL`` would still
        # satisfy a substring check on 'content_hash' but change index
        # semantics. Pin the operator explicitly.
        assert " ? " in predicate or "metadata ? " in predicate, (
            f"partial predicate operator drifted from jsonb '?': {predicate!r}"
        )


# ---------------------------------------------------------------------------
# Based-on guard: AUDIT_LOG_DDL must reflect every audit_log migration up to
# the constant pinned in conftest.
# ---------------------------------------------------------------------------
# Glob-scans the gubbi sibling repo for ``*audit_log*.py`` Alembic
# revisions, parses the ``YYYYMMDD_NNNN`` prefix from each filename, and
# asserts the maximum is <= ``AUDIT_LOG_DDL_BASED_ON``. A newer
# migration than the pin means ``AUDIT_LOG_DDL`` in conftest is stale
# and dedup/drift tests are exercising a pre-migration shape.
_REV_PREFIX_RE = re.compile(r"^(\d{8}_\d{4})_")


def test_audit_ddl_based_on_matches_latest_migration() -> None:
    """Fail when ``AUDIT_LOG_DDL_BASED_ON`` is behind the latest gubbi audit_log migration.

    Skips when the gubbi sibling repo is not present alongside
    gubbi-common, unless ``REQUIRE_GUBBI_MIGRATIONS=1`` makes absence a
    failure (the CI integration lane). When the sibling is present, every
    ``gubbi/alembic/versions/*audit_log*.py`` revision must be <=
    ``AUDIT_LOG_DDL_BASED_ON``. If a newer revision has landed, refresh
    ``AUDIT_LOG_DDL`` in conftest.py to reflect it and bump
    ``AUDIT_LOG_DDL_BASED_ON`` to match.
    """
    from tests.integration.conftest import (
        AUDIT_LOG_DDL_BASED_ON,
        MIGRATION_DDL_PATH,
        require_migration_source,
    )

    require_migration_source("audit_log based-on guard")

    matches = sorted(MIGRATION_DDL_PATH.glob("*audit_log*.py"))
    assert matches, (
        f"no *audit_log*.py revision found in {MIGRATION_DDL_PATH}; the based-on "
        "guard cannot measure staleness against an empty set"
    )

    revs: list[str] = []
    for path in matches:
        m = _REV_PREFIX_RE.match(path.name)
        if m is None:
            continue
        revs.append(m.group(1))

    assert revs, f"could not parse any YYYYMMDD_NNNN prefix from {[p.name for p in matches]}"
    latest = max(revs)
    assert latest <= AUDIT_LOG_DDL_BASED_ON, (
        f"gubbi audit_log migration {latest!r} is newer than the vendored "
        f"AUDIT_LOG_DDL based-on pin {AUDIT_LOG_DDL_BASED_ON!r}. Refresh "
        "AUDIT_LOG_DDL in tests/integration/conftest.py to reflect the new "
        "migration and bump AUDIT_LOG_DDL_BASED_ON to match."
    )


# ---------------------------------------------------------------------------
# Fixture contract: EFFECTIVE app-role exposure on audit_log.
# ---------------------------------------------------------------------------
# The deduped INSERT's ON CONFLICT inference reads five columns, so the app
# role needs a column-level SELECT grant AND a permissive SELECT policy.
# Either half alone fails: the grant alone trips row-level security, the
# policy alone trips the column ACL.
#
# These tests measure EFFECTIVE exposure, not the directly-granted rows in
# ``information_schema``. A grant reaching the app role through PUBLIC or
# through an inherited parent role does not appear as a row with the app
# role as grantee, so a catalog-row query reports the narrow set while the
# role can in fact read more. ``has_column_privilege`` /
# ``has_table_privilege`` resolve the full chain, and policy applicability
# is resolved with ``pg_has_role`` plus an explicit PUBLIC check. Each
# widening below is exercised as a live mutation with a canonical restore
# and a paired control proving the assertion was live.


async def _effective_select_columns(conn: asyncpg.Connection) -> set[str]:
    """Return every audit_log column the app role can effectively SELECT.

    Resolves direct grants, PUBLIC grants and grants inherited through
    role membership, which is what the role can actually read.
    """
    rows = await conn.fetch(
        """
        SELECT a.attname AS column_name
        FROM pg_attribute a
        WHERE a.attrelid = 'audit_log'::regclass
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND has_column_privilege($1, a.attrelid, a.attname, 'SELECT')
        """,
        AUDIT_LOG_APP_ROLE,
    )
    return {row["column_name"] for row in rows}


async def _has_table_select(conn: asyncpg.Connection) -> bool:
    granted = await conn.fetchval(
        "SELECT has_table_privilege($1, 'audit_log', 'SELECT')",
        AUDIT_LOG_APP_ROLE,
    )
    return bool(granted)


async def _applicable_read_policies(conn: asyncpg.Connection) -> list[asyncpg.Record]:
    """Return policies that can grant the app role read access.

    Covers ``FOR SELECT`` and ``FOR ALL`` (which includes reads), and
    treats a policy as applicable when it targets PUBLIC or any role the
    app role is a member of.
    """
    rows = await conn.fetch(
        """
        SELECT policyname, cmd, permissive, roles::text[] AS roles, qual
        FROM pg_policies
        WHERE tablename = 'audit_log'
          AND cmd IN ('SELECT', 'ALL')
          AND EXISTS (
              SELECT 1
              FROM unnest(roles::text[]) AS r
              WHERE r = 'public' OR pg_has_role($1, r, 'USAGE')
          )
        ORDER BY policyname
        """,
        AUDIT_LOG_APP_ROLE,
    )
    return list(rows)


@pytest.mark.asyncio(loop_scope="session")
async def test_app_role_effectively_reads_exactly_the_five_conflict_columns(
    pg_pool: asyncpg.Pool,
) -> None:
    # Arrange / Act
    async with pg_pool.acquire() as conn:
        effective = await _effective_select_columns(conn)

    # Assert
    assert effective == set(AUDIT_LOG_APP_SELECT_COLUMNS), (
        f"effective app-role SELECT set is {sorted(effective)}, expected exactly "
        f"{sorted(AUDIT_LOG_APP_SELECT_COLUMNS)}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_app_role_has_no_effective_table_wide_select(pg_pool: asyncpg.Pool) -> None:
    # Arrange / Act
    async with pg_pool.acquire() as conn:
        table_wide = await _has_table_select(conn)
        effective = await _effective_select_columns(conn)

    # Assert
    assert not table_wide, "app role holds effective table-wide SELECT on audit_log"
    for column in AUDIT_LOG_APP_DENIED_COLUMNS:
        assert column not in effective, f"{column!r} became effectively readable by the app role"


@pytest.mark.asyncio(loop_scope="session")
async def test_exactly_one_read_policy_applies_to_the_app_role(pg_pool: asyncpg.Pool) -> None:
    """One permissive self-only SELECT policy, and no FOR ALL policy reaching the role."""
    # Arrange / Act
    async with pg_pool.acquire() as conn:
        policies = await _applicable_read_policies(conn)

    # Assert
    assert len(policies) == 1, (
        "expected exactly one read policy applicable to the app role, got "
        f"{[(row['policyname'], row['cmd'], row['roles']) for row in policies]}"
    )
    policy = policies[0]
    assert policy["policyname"] == AUDIT_LOG_APP_SELECT_POLICY
    assert policy["cmd"] == "SELECT"
    assert policy["permissive"] == "PERMISSIVE"
    assert list(policy["roles"]) == [AUDIT_LOG_APP_ROLE]


@pytest.mark.asyncio(loop_scope="session")
async def test_select_policy_predicate_is_the_self_only_contract(pg_pool: asyncpg.Pool) -> None:
    """The read predicate matches the contract literal, not merely the write predicate."""
    # Arrange / Act
    async with pg_pool.acquire() as conn:
        select_qual = await conn.fetchval(
            "SELECT qual FROM pg_policies WHERE tablename = 'audit_log' AND policyname = $1",
            AUDIT_LOG_APP_SELECT_POLICY,
        )

    # Assert
    assert normalize_predicate(select_qual) == normalize_predicate(AUDIT_LOG_SELF_ONLY_PREDICATE), (
        f"read predicate drifted from the self-only contract: {select_qual!r}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_insert_policy_predicate_is_the_self_only_contract(pg_pool: asyncpg.Pool) -> None:
    """The write predicate matches the contract literal, independently of the read one."""
    # Arrange / Act
    async with pg_pool.acquire() as conn:
        insert_check = await conn.fetchval(
            "SELECT with_check FROM pg_policies WHERE tablename = 'audit_log' AND policyname = $1",
            AUDIT_LOG_APP_INSERT_POLICY,
        )

    # Assert
    assert normalize_predicate(insert_check) == normalize_predicate(
        AUDIT_LOG_SELF_ONLY_PREDICATE
    ), f"write predicate drifted from the self-only contract: {insert_check!r}"


@pytest.mark.asyncio(loop_scope="session")
async def test_read_and_write_predicates_agree(pg_pool: asyncpg.Pool) -> None:
    """The read surface is exactly the write surface.

    Kept alongside the two contract-literal tests: this one catches a
    divergence between the halves, those catch a widening of both.
    """
    # Arrange / Act
    async with pg_pool.acquire() as conn:
        select_qual = await conn.fetchval(
            "SELECT qual FROM pg_policies WHERE tablename = 'audit_log' AND policyname = $1",
            AUDIT_LOG_APP_SELECT_POLICY,
        )
        insert_check = await conn.fetchval(
            "SELECT with_check FROM pg_policies WHERE tablename = 'audit_log' AND policyname = $1",
            AUDIT_LOG_APP_INSERT_POLICY,
        )

    # Assert
    assert normalize_predicate(select_qual) == normalize_predicate(insert_check)


@pytest.mark.asyncio(loop_scope="session")
async def test_audit_log_enforces_row_level_security_for_every_role(
    pg_pool: asyncpg.Pool,
) -> None:
    """ENABLE alone exempts the table owner; FORCE is what makes policies universal."""
    # Arrange / Act
    async with pg_pool.acquire() as conn:
        flags = await conn.fetchrow(
            """
            SELECT relrowsecurity, relforcerowsecurity
            FROM pg_class
            WHERE oid = 'audit_log'::regclass
            """
        )

    # Assert
    assert flags["relrowsecurity"] is True, "row-level security is off; policies are inert"
    assert flags["relforcerowsecurity"] is True, (
        "row-level security is not FORCEd, so the table owner bypasses the self-only policies"
    )


# ---------------------------------------------------------------------------
# Live widening mutations: each assertion above must be able to fail.
# ---------------------------------------------------------------------------
# Every case widens the real schema in the container, re-measures, asserts
# the widening IS observed, then restores canonically and asserts the
# narrow state is back. The restore assertion is the paired control: it
# proves the mutation was undone rather than never applied, so a later
# test in the session cannot inherit a widened schema.
#
# These four widenings are exactly the ones a catalog-row query misses or
# a predicate-equality check tolerates -- PUBLIC table SELECT, a parent
# role's column grant, a PUBLIC FOR ALL policy, an inherited extra
# policy, and both predicates widened together.

_PROBE_PARENT_ROLE: Final[str] = "probe_parent_role"
_PROBE_ALL_POLICY: Final[str] = "probe_public_all_policy"
_PROBE_PARENT_POLICY: Final[str] = "probe_parent_select_policy"


@asynccontextmanager
async def _widened(
    conn: asyncpg.Connection, widen: Sequence[str], restore: Sequence[str]
) -> AsyncIterator[None]:
    """Apply *widen*, yield, then always apply *restore*."""
    for statement in widen:
        await conn.execute(statement)
    try:
        yield
    finally:
        for statement in restore:
            await conn.execute(statement)


@pytest.mark.asyncio(loop_scope="session")
async def test_public_table_select_grant_is_detected_and_restored(
    pg_pool: asyncpg.Pool,
) -> None:
    """A PUBLIC grant reaches the app role without naming it as grantee."""
    async with pg_pool.acquire() as conn:
        async with _widened(
            conn,
            ["GRANT SELECT ON TABLE audit_log TO PUBLIC"],
            ["REVOKE SELECT ON TABLE audit_log FROM PUBLIC"],
        ):
            # Assert: the widening is observed on both surfaces.
            assert await _has_table_select(conn) is True
            widened_columns = await _effective_select_columns(conn)
            assert widened_columns > set(AUDIT_LOG_APP_SELECT_COLUMNS)
            for column in AUDIT_LOG_APP_DENIED_COLUMNS:
                assert column in widened_columns

        # Paired control: canonical state is back.
        assert await _has_table_select(conn) is False
        assert await _effective_select_columns(conn) == set(AUDIT_LOG_APP_SELECT_COLUMNS)


@pytest.mark.asyncio(loop_scope="session")
async def test_parent_role_column_grant_is_detected_and_restored(
    pg_pool: asyncpg.Pool,
) -> None:
    """An inherited column grant is invisible to a grantee-keyed catalog query."""
    async with pg_pool.acquire() as conn:
        async with _widened(
            conn,
            [
                f"CREATE ROLE {_PROBE_PARENT_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS",
                f"GRANT {_PROBE_PARENT_ROLE} TO {AUDIT_LOG_APP_ROLE}",
                f"GRANT SELECT (reason) ON TABLE audit_log TO {_PROBE_PARENT_ROLE}",
            ],
            [
                # Interpolated identifiers are module constants, and DDL
                # cannot bind them as parameters; the REVOKE reads as a
                # SELECT ... FROM to the scanner.
                f"REVOKE SELECT (reason) ON TABLE audit_log FROM {_PROBE_PARENT_ROLE}",  # noqa: S608
                f"REVOKE {_PROBE_PARENT_ROLE} FROM {AUDIT_LOG_APP_ROLE}",
                f"DROP ROLE {_PROBE_PARENT_ROLE}",
            ],
        ):
            widened_columns = await _effective_select_columns(conn)

            # Assert: effective measurement catches it...
            assert "reason" in widened_columns
            assert widened_columns != set(AUDIT_LOG_APP_SELECT_COLUMNS)

            # ...while the direct-grantee catalog view does not, which is
            # why the tests above must not use it.
            direct = await conn.fetch(
                """
                SELECT column_name
                FROM information_schema.column_privileges
                WHERE table_name = 'audit_log'
                  AND grantee = $1
                  AND privilege_type = 'SELECT'
                """,
                AUDIT_LOG_APP_ROLE,
            )
            assert {row["column_name"] for row in direct} == set(AUDIT_LOG_APP_SELECT_COLUMNS)

        # Paired control.
        assert await _effective_select_columns(conn) == set(AUDIT_LOG_APP_SELECT_COLUMNS)


@pytest.mark.asyncio(loop_scope="session")
async def test_public_for_all_policy_is_detected_and_restored(pg_pool: asyncpg.Pool) -> None:
    """``FOR ALL`` includes reads, and PUBLIC reaches every role."""
    async with pg_pool.acquire() as conn:
        async with _widened(
            conn,
            [f"CREATE POLICY {_PROBE_ALL_POLICY} ON audit_log FOR ALL USING (true)"],
            [f"DROP POLICY {_PROBE_ALL_POLICY} ON audit_log"],
        ):
            policies = await _applicable_read_policies(conn)
            names = [row["policyname"] for row in policies]

            # Assert
            assert _PROBE_ALL_POLICY in names
            assert len(policies) == 2

        # Paired control.
        restored = await _applicable_read_policies(conn)
        assert [row["policyname"] for row in restored] == [AUDIT_LOG_APP_SELECT_POLICY]


@pytest.mark.asyncio(loop_scope="session")
async def test_inherited_extra_select_policy_is_detected_and_restored(
    pg_pool: asyncpg.Pool,
) -> None:
    """A policy granted to a parent role still applies to the app role."""
    async with pg_pool.acquire() as conn:
        async with _widened(
            conn,
            [
                f"CREATE ROLE {_PROBE_PARENT_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS",
                f"GRANT {_PROBE_PARENT_ROLE} TO {AUDIT_LOG_APP_ROLE}",
                f"CREATE POLICY {_PROBE_PARENT_POLICY} ON audit_log "
                f"FOR SELECT TO {_PROBE_PARENT_ROLE} USING (true)",
            ],
            [
                f"DROP POLICY {_PROBE_PARENT_POLICY} ON audit_log",
                f"REVOKE {_PROBE_PARENT_ROLE} FROM {AUDIT_LOG_APP_ROLE}",
                f"DROP ROLE {_PROBE_PARENT_ROLE}",
            ],
        ):
            policies = await _applicable_read_policies(conn)

            # Assert
            assert _PROBE_PARENT_POLICY in [row["policyname"] for row in policies]
            assert len(policies) == 2

        # Paired control.
        restored = await _applicable_read_policies(conn)
        assert [row["policyname"] for row in restored] == [AUDIT_LOG_APP_SELECT_POLICY]


@pytest.mark.asyncio(loop_scope="session")
async def test_both_predicates_widened_together_is_detected_and_restored(
    pg_pool: asyncpg.Pool,
) -> None:
    """Widening BOTH halves keeps them equal -- only the contract literal catches it."""
    canonical_select = (
        f"CREATE POLICY {AUDIT_LOG_APP_SELECT_POLICY} ON audit_log "
        f"FOR SELECT TO {AUDIT_LOG_APP_ROLE} USING {AUDIT_LOG_SELF_ONLY_PREDICATE}"
    )
    canonical_insert = (
        f"CREATE POLICY {AUDIT_LOG_APP_INSERT_POLICY} ON audit_log "
        f"FOR INSERT TO {AUDIT_LOG_APP_ROLE} WITH CHECK {AUDIT_LOG_SELF_ONLY_PREDICATE}"
    )

    async with pg_pool.acquire() as conn:
        async with _widened(
            conn,
            [
                f"DROP POLICY {AUDIT_LOG_APP_SELECT_POLICY} ON audit_log",
                f"DROP POLICY {AUDIT_LOG_APP_INSERT_POLICY} ON audit_log",
                f"CREATE POLICY {AUDIT_LOG_APP_SELECT_POLICY} ON audit_log "
                f"FOR SELECT TO {AUDIT_LOG_APP_ROLE} USING (true)",
                f"CREATE POLICY {AUDIT_LOG_APP_INSERT_POLICY} ON audit_log "
                f"FOR INSERT TO {AUDIT_LOG_APP_ROLE} WITH CHECK (true)",
            ],
            [
                f"DROP POLICY {AUDIT_LOG_APP_SELECT_POLICY} ON audit_log",
                f"DROP POLICY {AUDIT_LOG_APP_INSERT_POLICY} ON audit_log",
                canonical_select,
                canonical_insert,
            ],
        ):
            select_qual = await conn.fetchval(
                "SELECT qual FROM pg_policies WHERE tablename = 'audit_log' AND policyname = $1",
                AUDIT_LOG_APP_SELECT_POLICY,
            )
            insert_check = await conn.fetchval(
                """
                SELECT with_check FROM pg_policies
                WHERE tablename = 'audit_log' AND policyname = $1
                """,
                AUDIT_LOG_APP_INSERT_POLICY,
            )

            # Assert: equality still holds, so the halves-agree check is
            # blind here; the contract-literal checks are what fail.
            assert normalize_predicate(select_qual) == normalize_predicate(insert_check)
            contract = normalize_predicate(AUDIT_LOG_SELF_ONLY_PREDICATE)
            assert normalize_predicate(select_qual) != contract
            assert normalize_predicate(insert_check) != contract

        # Paired control: both predicates are the contract again.
        select_qual = await conn.fetchval(
            "SELECT qual FROM pg_policies WHERE tablename = 'audit_log' AND policyname = $1",
            AUDIT_LOG_APP_SELECT_POLICY,
        )
        insert_check = await conn.fetchval(
            "SELECT with_check FROM pg_policies WHERE tablename = 'audit_log' AND policyname = $1",
            AUDIT_LOG_APP_INSERT_POLICY,
        )
        contract = normalize_predicate(AUDIT_LOG_SELF_ONLY_PREDICATE)
        assert normalize_predicate(select_qual) == contract
        assert normalize_predicate(insert_check) == contract
