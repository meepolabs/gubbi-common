"""Postgres log-settings ``StartupProbe`` wrapper.

Wraps :func:`gubbi_common.bootstrap.pg_log_probe._probe_pg_log_settings`
in a ``StartupProbe`` shape so
:class:`gubbi_common.bootstrap.StartupRunner` can sequence it alongside
other startup probes.  Mode is consumed from
``settings.pg_log_probe_mode`` (``STRICT`` / ``WARN`` / ``OFF``):
``STRICT`` raises on any unsafe GUC; ``WARN`` logs in-place and returns;
``OFF`` skips the probe entirely.

The STRICT-mode :class:`PgLogProbeError` is caught here and surfaced as
a structured FAIL :class:`ProbeResult` (mode + findings diagnostic) so
HyperDX dashboards see the same shape across consumers, instead of a
generic ``error_type=PgLogProbeError`` / ``error_message=<stringified>``
from the runner's catch-all path.

Required: the underlying contract is a security guard that a
misconfigured operator must not silently bypass; the cluster log
settings could otherwise turn the database into a plaintext sink for
journal content.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gubbi_common.bootstrap.pg_log_probe import (
    PgLogProbeError,
    PgLogProbeMode,
    _probe_pg_log_settings,
)
from gubbi_common.bootstrap.probe_runner import ProbeResult, ProbeStatus

if TYPE_CHECKING:
    import asyncpg

__all__ = ["PgLogProbe"]


@dataclass
class PgLogProbe:
    """Probe that fails when Postgres log GUCs would capture plaintext.

    Constructor-injected wrapper around
    :func:`gubbi_common.bootstrap.pg_log_probe._probe_pg_log_settings`.  STRICT mode
    raises on any unsafe setting; the wrapper catches the exception and
    returns a structured FAIL ``ProbeResult`` so the diagnostic shape
    matches across consumers (mode + findings).

    Attributes:
        pool: Connected ``asyncpg.Pool``.  The cluster GUCs are
            pool-independent but cloud-api passes the App-role pool to
            keep the call shape consistent with sibling probes that
            read tenant-scoped state.
        mode: ``PgLogProbeMode`` resolved from
            ``settings.pg_log_probe_mode``.
    """

    pool: asyncpg.Pool
    mode: PgLogProbeMode
    name: str = "pg_log"
    required: bool = True
    timeout_s: float = 5.0

    async def run(self) -> ProbeResult:
        """Check Postgres log GUCs; fail or warn per ``mode``.

        ``_probe_pg_log_settings`` raises ``PgLogProbeError`` only in
        STRICT mode -- WARN logs in-place and returns; OFF skips the
        DB query.  So the except branch fires only when STRICT detected
        unsafe GUCs; ``required=True`` makes the FAIL escalate to
        ``ProbeFailure`` and abort boot.
        """
        try:
            await _probe_pg_log_settings(self.pool, mode=self.mode)
        except PgLogProbeError as exc:
            return ProbeResult(
                ProbeStatus.FAIL,
                diagnostic={"mode": self.mode.value, "findings": str(exc)},
            )
        return ProbeResult(ProbeStatus.OK, diagnostic={"mode": self.mode.value})
