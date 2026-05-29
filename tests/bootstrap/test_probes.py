"""Tests for ``gubbi_common.bootstrap.probes`` (PgLogProbe, RedisPingProbe).

These are the StartupProbe wrappers promoted from gubbi/gubbi-cloud at
T2 (lifespan-probe streamline) so both consumers compose the same shape
through ``StartupRunner``.  The tests pin:

* PgLogProbe: STRICT-mode failure surfaces as a structured FAIL outcome
  (mode + findings diagnostic), WARN/OFF return OK with mode diagnostic.
* RedisPingProbe: happy-path PING returns OK; exceptions propagate to
  the runner so the runner's central credential-scrubbing applies.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from gubbi_common.bootstrap import (
    PgLogProbeError,
    PgLogProbeMode,
    ProbeStatus,
)
from gubbi_common.bootstrap.probes import PgLogProbe, RedisPingProbe

# Settings the underlying probe consults via ``current_setting(name, true)``.
_SAFE_SETTINGS = {
    "log_statement": "none",
    "log_min_duration_statement": "-1",
    "log_parameter_max_length": "0",
    "auto_explain.log_min_duration": "-1",
    "pg_stat_statements.track": "top",
}


def _make_pool(settings: dict[str, str]) -> Any:
    """Build a mock asyncpg pool whose ``current_setting($1)`` returns *settings*."""
    conn = MagicMock()

    async def fetchval(sql: str, *args: Any) -> str | None:
        del sql
        if not args:
            return None
        return settings.get(args[0])

    conn.fetchval = AsyncMock(side_effect=fetchval)
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


# ---------------------------------------------------------------------------
# PgLogProbe -- shared shape for gubbi + gubbi-cloud + extraction worker.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pg_log_probe_ok_in_strict_when_settings_safe() -> None:
    # Arrange
    pool = _make_pool(_SAFE_SETTINGS)
    probe = PgLogProbe(pool=pool, mode=PgLogProbeMode.STRICT)

    # Act
    result = await probe.run()

    # Assert
    assert result.status is ProbeStatus.OK
    assert result.diagnostic == {"mode": "strict"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pg_log_probe_strict_mode_fail_carries_findings_diagnostic() -> None:
    """STRICT-mode unsafe GUC -> FAIL with mode + findings, not a runner-shaped error_type."""
    # Arrange
    pool = _make_pool({**_SAFE_SETTINGS, "log_statement": "all"})
    probe = PgLogProbe(pool=pool, mode=PgLogProbeMode.STRICT)

    # Act
    result = await probe.run()

    # Assert
    assert result.status is ProbeStatus.FAIL
    diag = dict(result.diagnostic)
    assert diag["mode"] == "strict"
    assert "log_statement" in diag["findings"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pg_log_probe_warn_mode_returns_ok_with_mode_diagnostic(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """WARN mode logs the finding in-place but the probe returns OK to the runner."""
    import logging

    # Arrange
    pool = _make_pool({**_SAFE_SETTINGS, "log_statement": "all"})
    probe = PgLogProbe(pool=pool, mode=PgLogProbeMode.WARN)

    # Act
    with caplog.at_level(logging.WARNING, logger="gubbi_common.bootstrap.pg_log_probe"):
        result = await probe.run()

    # Assert
    assert result.status is ProbeStatus.OK
    assert result.diagnostic == {"mode": "warn"}
    assert any("log_statement" in record.message for record in caplog.records)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pg_log_probe_off_mode_returns_ok_without_db_query() -> None:
    """OFF returns OK without hitting the pool."""
    # Arrange
    pool = _make_pool({**_SAFE_SETTINGS, "log_statement": "all"})
    probe = PgLogProbe(pool=pool, mode=PgLogProbeMode.OFF)

    # Act
    result = await probe.run()

    # Assert
    assert result.status is ProbeStatus.OK
    assert result.diagnostic == {"mode": "off"}
    conn = pool.acquire.return_value.__aenter__.return_value
    conn.fetchval.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pg_log_probe_propagates_underlying_pg_log_probe_error_via_caught_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A direct ``PgLogProbeError`` raised by the helper still surfaces as FAIL.

    Belt-and-braces: even if the helper raises an error whose
    ``str(exc)`` is the entire findings block, the wrapper re-shapes it
    as FAIL with the canonical mode + findings diagnostic instead of
    letting the runner's catch-all path stamp ``error_type=PgLogProbeError``.
    """

    async def _raise(_pool: Any, *, mode: PgLogProbeMode | str) -> None:
        del mode
        raise PgLogProbeError("Unsafe Postgres log settings detected:\n  - log_statement=all")

    monkeypatch.setattr(
        "gubbi_common.bootstrap.probes.pg_log._probe_pg_log_settings",
        _raise,
    )

    # Arrange
    probe = PgLogProbe(pool=MagicMock(), mode=PgLogProbeMode.STRICT)

    # Act
    result = await probe.run()

    # Assert
    assert result.status is ProbeStatus.FAIL
    diag = dict(result.diagnostic)
    assert diag["mode"] == "strict"
    assert "log_statement=all" in diag["findings"]


# ---------------------------------------------------------------------------
# RedisPingProbe -- shared shape; exception propagates to the runner.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_redis_ping_probe_ok_when_ping_returns() -> None:
    # Arrange
    client = MagicMock()
    client.ping = AsyncMock(return_value=b"PONG")
    probe = RedisPingProbe(client=client)

    # Act
    result = await probe.run()

    # Assert
    assert result.status is ProbeStatus.OK
    assert dict(result.diagnostic) == {}
    client.ping.assert_awaited_once()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_redis_ping_probe_propagates_connection_error_to_runner() -> None:
    """Driver exceptions bubble out so the runner can populate ``error_type`` + scrub creds.

    The probe does NOT trap the exception itself: the runner's
    ``except Exception`` arm sets ``error_type``,
    ``error_message`` (URL-credential scrubbed), and the
    ``startup.probe.fail`` structured event.  Re-shaping into a
    probe-author-supplied diagnostic would bypass that scrubbing path.

    ``redis-py`` is not a dependency of ``gubbi-common`` (the wrapper
    type-checks the client via ``TYPE_CHECKING``-only import).  The test
    therefore uses a plain ``ConnectionError`` -- the contract is
    "exception bubbles up", not "this specific class bubbles up".
    """
    # Arrange
    client = MagicMock()
    client.ping = AsyncMock(side_effect=ConnectionError("simulated_redis_unreachable"))
    probe = RedisPingProbe(client=client)

    # Act + Assert
    with pytest.raises(ConnectionError, match="simulated_redis_unreachable"):
        await probe.run()
    client.ping.assert_awaited_once()


@pytest.mark.unit
def test_pg_log_probe_default_attributes() -> None:
    """Defaults pin the StartupProbe Protocol shape callers rely on."""
    probe = PgLogProbe(pool=MagicMock(), mode=PgLogProbeMode.STRICT)
    assert probe.name == "pg_log"
    assert probe.required is True
    assert probe.timeout_s == 5.0


@pytest.mark.unit
def test_redis_ping_probe_default_attributes() -> None:
    """Defaults pin the StartupProbe Protocol shape callers rely on."""
    probe = RedisPingProbe(client=MagicMock())
    assert probe.name == "redis_ping"
    assert probe.required is True
    assert probe.timeout_s == 5.0
