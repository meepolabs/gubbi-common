"""Test helpers for the StartupProbe contract.

RecordingProbeRunner: capture (name, required) tuples for the probes
that would have been run, without actually invoking probe.run(). Used
by consumer apps to pin canonical probe order in lifespan smoke tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    import structlog

    from gubbi_common.bootstrap.probe_runner import ProbeOutcome, StartupProbe

__all__ = [
    "RecordedProbe",
    "RecordingProbeRunner",
]


@dataclass(frozen=True)
class RecordedProbe:
    """Snapshot of a probe's (name, required) at the moment ``run`` was called."""

    name: str
    required: bool


class RecordingProbeRunner:
    """Stand-in for StartupRunner that records probe order without invoking.

    Capture-only: ``probe.run()`` is NEVER called. The recorded list
    captures ``(name, required)`` for each probe, in declared order.
    Consumers assert against this list to pin their canonical lifespan
    probe order.
    """

    def __init__(self) -> None:
        self.recorded: list[RecordedProbe] = []

    async def run(
        self,
        probes: Sequence[StartupProbe],
        *,
        logger: structlog.stdlib.AsyncBoundLogger | None = None,
    ) -> tuple[ProbeOutcome, ...]:
        """Record the probe order; return an empty outcomes tuple."""
        del logger  # accepted for signature parity with StartupRunner.run
        self.recorded = [RecordedProbe(p.name, p.required) for p in probes]
        return ()
