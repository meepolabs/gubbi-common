"""Postgres log/extension settings probe.

Inspects a small set of cluster-side knobs that, when configured loudly,
cause untruncated SQL parameters or full statement text to land in the
Postgres log. Since the application has no control over those log files
(they belong to the DBA / hosting layer), enabling these settings would
silently turn the database into a plaintext logging sink for journal
content.

The probe is wired by consumers into their startup lifecycle; it is NOT
invoked from this module. Three modes:

* ``STRICT`` -- raise ``PgLogProbeError`` on any unsafe setting (default
  for hosted production).
* ``WARN`` -- log a warning and continue (transitional mode).
* ``OFF`` -- skip the probe entirely (self-hosters who accept the risk).

Consumers wire mode selection from an env var (e.g.
``JOURNAL_PG_LOG_PROBE_MODE``); this module does not read environment
variables. The handshake is intentional: env-var policy belongs to each
service, not the shared library.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    import asyncpg

__all__ = [
    "PgLogProbeError",
    "PgLogProbeMode",
    "probe_pg_log_settings",
]

logger = logging.getLogger(__name__)


class PgLogProbeMode(StrEnum):
    """How strictly the probe should react to an unsafe setting."""

    STRICT = "strict"
    WARN = "warn"
    OFF = "off"


class PgLogProbeError(RuntimeError):
    """Raised in STRICT mode when an unsafe Postgres log setting is detected."""


# Each entry: (setting name, predicate(value) -> bool, description for the error message).
# The predicate returns True when the value is UNSAFE -- i.e. the
# setting is loud enough to capture statement text or parameters in the
# Postgres log. None values (extension not loaded, setting unknown) are
# always treated as safe; ``current_setting(name, true)`` returns NULL
# in that case.
def _is_loud_log_statement(value: str) -> bool:
    # "mod" logs all DDL + data-modifying DML *with bound parameter values*
    # -- the same plaintext-leak surface as "all" for any INSERT/UPDATE/DELETE.
    return value.lower() in {"all", "mod"}


def _is_nonneg_int(value: str) -> bool:
    try:
        return int(value) >= 0
    except (TypeError, ValueError):
        return False


def _is_log_param_capture(value: str) -> bool:
    """Return True when ``log_parameter_max_length`` captures bound parameters.

    PG14+ semantics for ``log_parameter_max_length``:

    * ``0`` -- bound parameters are NEVER captured in the cluster log
      (safe; this is what we want).
    * any other integer -- bound parameters ARE captured. ``-1`` means
      "unlimited" (the maximally unsafe value); a positive integer is a
      truncation cap that still captures values up to the cap.

    Non-integer or unparseable strings are treated as safe (the setting
    is not actively enabling capture).
    """
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        return False


def _is_track_all(value: str) -> bool:
    return value.lower() == "all"


_PROBES: tuple[tuple[str, Callable[[str], bool], str], ...] = (
    (
        "log_statement",
        _is_loud_log_statement,
        "log_statement={value} captures full SQL text in the cluster log",
    ),
    (
        "log_min_duration_statement",
        _is_nonneg_int,
        "log_min_duration_statement={value} captures every statement >= that ms threshold",
    ),
    (
        "log_parameter_max_length",
        _is_log_param_capture,
        "log_parameter_max_length={value} captures bound parameters in the cluster log",
    ),
    (
        "auto_explain.log_min_duration",
        _is_nonneg_int,
        "auto_explain.log_min_duration={value} captures plans + parameters in the cluster log",
    ),
    (
        "pg_stat_statements.track",
        _is_track_all,
        "pg_stat_statements.track={value} retains every statement (including utility) "
        "in shared memory",
    ),
)


async def probe_pg_log_settings(
    pool: asyncpg.Pool,
    *,
    mode: PgLogProbeMode | str = PgLogProbeMode.STRICT,
) -> None:
    """Inspect Postgres log settings; act per *mode* on unsafe values.

    Parameters
    ----------
    pool:
        Connected ``asyncpg.Pool``. The probe acquires one connection,
        runs five ``SELECT current_setting('<name>', true)`` calls, and
        releases it.
    mode:
        Either a ``PgLogProbeMode`` member or a bare string
        (``"strict"``, ``"warn"``, ``"off"``); StrEnum makes both forms
        work without an explicit conversion at the call site.

    Raises
    ------
    ValueError
        If ``mode`` is not one of the three accepted values.
    PgLogProbeError
        In ``STRICT`` mode, when any unsafe setting is detected.
    """
    try:
        resolved_mode = PgLogProbeMode(mode)
    except ValueError as exc:
        raise ValueError(
            f"probe_pg_log_settings: mode must be one of "
            f"{[m.value for m in PgLogProbeMode]}; got {mode!r}"
        ) from exc

    if resolved_mode is PgLogProbeMode.OFF:
        logger.warning("pg_log_probe: mode=OFF -- Postgres log settings not inspected")
        return

    findings: list[str] = []
    async with pool.acquire() as conn:
        for name, is_unsafe, template in _PROBES:
            value = await conn.fetchval("SELECT current_setting($1, true)", name)
            if value is None:
                continue
            if is_unsafe(value):
                findings.append(template.format(value=value))

    if not findings:
        return

    if resolved_mode is PgLogProbeMode.STRICT:
        raise PgLogProbeError(
            "Unsafe Postgres log settings detected:\n  - " + "\n  - ".join(findings)
        )
    # WARN
    for finding in findings:
        logger.warning("pg_log_probe: %s", finding)
