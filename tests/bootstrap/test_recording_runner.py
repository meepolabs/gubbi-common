"""Tests for ``gubbi_common.bootstrap.testing.RecordingProbeRunner``.

The recording runner stands in for ``StartupRunner`` in lifespan smoke
tests: it captures the (name, required) tuples in declared order WITHOUT
invoking ``probe.run()``. Consumers use this to pin canonical lifespan
probe order without spinning up real dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from gubbi_common.bootstrap import (
    ProbeResult,
    ProbeStatus,
    RecordedProbe,
    RecordingProbeRunner,
)


@dataclass
class _Probe:
    """Probe whose ``run()`` raises if invoked.

    Lets the test prove the recording runner DOES NOT call ``probe.run()``.
    """

    name: str
    required: bool
    timeout_s: float = 5.0

    async def run(self) -> ProbeResult:
        raise AssertionError(
            f"RecordingProbeRunner.run must not invoke probe.run(); got {self.name!r}"
        )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_recording_runner_captures_three_probes_in_order() -> None:
    probes = [
        _Probe(name="alpha", required=True),
        _Probe(name="beta", required=False),
        _Probe(name="gamma", required=True),
    ]
    runner = RecordingProbeRunner()

    outcomes = await runner.run(probes)

    assert outcomes == ()
    assert runner.recorded == [
        RecordedProbe(name="alpha", required=True),
        RecordedProbe(name="beta", required=False),
        RecordedProbe(name="gamma", required=True),
    ]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_recording_runner_does_not_invoke_run() -> None:
    """If ``probe.run()`` were invoked, the AssertionError would propagate."""
    probes = [_Probe(name="alpha", required=True)]
    runner = RecordingProbeRunner()

    # Must not raise.
    await runner.run(probes)

    # Positive assertion: the probe order WAS recorded even though
    # probe.run() was not invoked.
    assert runner.recorded == [RecordedProbe(name="alpha", required=True)]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_recording_runner_returns_empty_outcomes_tuple() -> None:
    runner = RecordingProbeRunner()

    result = await runner.run([])

    assert result == ()
    assert isinstance(result, tuple)
    assert runner.recorded == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_recording_runner_logger_kwarg_accepted() -> None:
    """The signature mirrors StartupRunner.run; passing logger=None is OK."""
    probes = [_Probe(name="alpha", required=True)]
    runner = RecordingProbeRunner()

    # Passing logger=None must work (signature parity).
    outcomes = await runner.run(probes, logger=None)

    assert outcomes == ()
    assert runner.recorded[0].name == "alpha"


@pytest.mark.unit
def test_recorded_probe_is_frozen() -> None:
    rec = RecordedProbe(name="x", required=True)
    # Frozen dataclasses raise FrozenInstanceError (subclass of
    # AttributeError) on attribute assignment; pin the precise type.
    with pytest.raises(AttributeError):
        rec.name = "y"  # type: ignore[misc]


@pytest.mark.unit
def test_probe_result_is_re_exported_for_recording_users() -> None:
    """The recording runner's caller often imports ProbeResult/Status alongside."""
    res = ProbeResult(status=ProbeStatus.OK)
    assert res.status is ProbeStatus.OK
