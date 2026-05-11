"""Tests for ``gubbi_common.bootstrap.pg_log_probe``.

The probe inspects Postgres log/extension settings that, in their loud
configurations, can capture untruncated SQL parameters or full statement
text in cluster logs -- which would smuggle journal content into a
plaintext sink the application has no control over. The probe is the
lifecycle gate: callers run it on startup and either fail (STRICT),
log (WARN), or skip (OFF).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from gubbi_common.bootstrap import (
    PgLogProbeError,
    PgLogProbeMode,
    probe_pg_log_settings,
)

# Settings the probe consults via ``current_setting(name, true)``.
# Order matters only for assertion clarity; the probe queries each in turn.
_SAFE_SETTINGS = {
    "log_statement": "none",
    "log_min_duration_statement": "-1",
    "log_parameter_max_length": "0",
    "auto_explain.log_min_duration": "-1",
    "pg_stat_statements.track": "top",
}


def make_pool(settings: dict[str, str]) -> Any:
    """Build a mock asyncpg pool that returns *settings* from ``current_setting``.

    The probe issues ``conn.fetchval("SELECT current_setting($1, true)", name)``
    -- a parameterised query (A-H3 fix). The mock therefore inspects the
    first positional argument, not the SQL string.
    """
    conn = MagicMock()

    async def fetchval(sql: str, *args: Any) -> str | None:
        if not args:
            return None
        name = args[0]
        return settings.get(name)

    conn.fetchval = AsyncMock(side_effect=fetchval)
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


@pytest.mark.asyncio
async def test_safe_settings_pass_strict() -> None:
    pool = make_pool(_SAFE_SETTINGS)
    await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_log_statement_all_strict_raises() -> None:
    pool = make_pool({**_SAFE_SETTINGS, "log_statement": "all"})
    with pytest.raises(PgLogProbeError, match="log_statement"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_log_statement_all_warn_logs_only(caplog: pytest.LogCaptureFixture) -> None:
    import logging

    pool = make_pool({**_SAFE_SETTINGS, "log_statement": "all"})
    with caplog.at_level(logging.WARNING, logger="gubbi_common.bootstrap.pg_log_probe"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.WARN)
    assert any("log_statement" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_off_mode_no_op(caplog: pytest.LogCaptureFixture) -> None:
    """OFF returns early without inspecting any setting, but emits a
    warning so the operator sees that the safety net is intentionally
    disabled (A-M5).
    """
    import logging

    pool = make_pool({**_SAFE_SETTINGS, "log_statement": "all"})
    with caplog.at_level(logging.WARNING, logger="gubbi_common.bootstrap.pg_log_probe"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.OFF)
    matching = [r for r in caplog.records if "mode=OFF" in r.message]
    assert len(matching) == 1, "expected exactly one OFF-mode warning"
    # And no settings were probed.
    conn = pool.acquire.return_value.__aenter__.return_value
    conn.fetchval.assert_not_called()


@pytest.mark.asyncio
async def test_log_min_duration_statement_zero_raises() -> None:
    """0 ms means log every statement; >= 0 is unsafe."""
    pool = make_pool({**_SAFE_SETTINGS, "log_min_duration_statement": "0"})
    with pytest.raises(PgLogProbeError, match="log_min_duration_statement"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_log_min_duration_statement_positive_raises() -> None:
    pool = make_pool({**_SAFE_SETTINGS, "log_min_duration_statement": "100"})
    with pytest.raises(PgLogProbeError, match="log_min_duration_statement"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_log_parameter_max_length_positive_raises() -> None:
    pool = make_pool({**_SAFE_SETTINGS, "log_parameter_max_length": "1024"})
    with pytest.raises(PgLogProbeError, match="log_parameter_max_length"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


# ---------------------------------------------------------------------------
# A-H5: log_parameter_max_length PG14+ semantics
# ---------------------------------------------------------------------------
# 0 means "no capture" (safe). Any other integer enables capture; -1 means
# "unlimited" (maximally unsafe). The dedicated _is_log_param_capture
# predicate flags everything except 0.


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe_value", ["-1", "1", "100", "1024"])
async def test_log_parameter_max_length_unsafe_values_raise(unsafe_value: str) -> None:
    """A-H5: -1 (unlimited) plus any positive int are unsafe in PG14+."""
    pool = make_pool({**_SAFE_SETTINGS, "log_parameter_max_length": unsafe_value})
    with pytest.raises(PgLogProbeError, match="log_parameter_max_length"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_log_parameter_max_length_zero_is_safe() -> None:
    """A-H5: 0 means parameters are NOT captured -- the safe value."""
    pool = make_pool({**_SAFE_SETTINGS, "log_parameter_max_length": "0"})
    # Must not raise.
    await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_auto_explain_log_min_duration_zero_raises() -> None:
    pool = make_pool({**_SAFE_SETTINGS, "auto_explain.log_min_duration": "0"})
    with pytest.raises(PgLogProbeError, match="auto_explain"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_pg_stat_statements_track_all_raises() -> None:
    pool = make_pool({**_SAFE_SETTINGS, "pg_stat_statements.track": "all"})
    with pytest.raises(PgLogProbeError, match="pg_stat_statements"):
        await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_unloaded_extension_treated_safe() -> None:
    """current_setting('<gname>', true) returns None when the extension is
    not loaded; the probe must treat absence as safe (the unsafe value is
    not active)."""
    pool = make_pool(
        {
            "log_statement": "none",
            "log_min_duration_statement": "-1",
            "log_parameter_max_length": "0",
            # auto_explain + pg_stat_statements absent (None)
        }
    )
    await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)


@pytest.mark.asyncio
async def test_invalid_mode_raises_value_error() -> None:
    pool = make_pool(_SAFE_SETTINGS)
    with pytest.raises(ValueError, match="mode"):
        await probe_pg_log_settings(pool, mode="loud")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_mode_string_accepted() -> None:
    """StrEnum-shaped: callers can pass 'strict' / 'warn' / 'off' as bare strings."""
    pool = make_pool(_SAFE_SETTINGS)
    await probe_pg_log_settings(pool, mode="strict")


@pytest.mark.asyncio
async def test_uses_parameterised_current_setting() -> None:
    """A-H3: GUC name flows through asyncpg parameter, not f-string interpolation.

    The probe must not interpolate the GUC name into the SQL string. We
    assert the SQL is the literal parameterised form and the name lands
    in the args.
    """
    pool = make_pool(_SAFE_SETTINGS)
    await probe_pg_log_settings(pool, mode=PgLogProbeMode.STRICT)

    # Recover the mock conn via the acquire context manager.
    conn = pool.acquire.return_value.__aenter__.return_value
    calls = conn.fetchval.await_args_list
    assert calls, "expected probe to call fetchval at least once"
    for call_obj in calls:
        sql = call_obj.args[0]
        # Parameterised form: literal SQL with $1 placeholder, no GUC name embedded.
        assert sql == "SELECT current_setting($1, true)"
        # GUC name lands in args[1] (positional after sql).
        assert call_obj.args[1] in _SAFE_SETTINGS
