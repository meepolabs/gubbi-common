"""Tests for ``gubbi_common.bootstrap.probe_runner``.

The runner orchestrates a sequence of ``StartupProbe`` instances with
per-probe timeouts, total wall-clock budget, OTel span emission, and
deque-buffered structured-event capture (``log_tail``) on FAIL/WARN.
These tests pin the contract that gubbi + gubbi-cloud + the extraction
worker depend on for their lifespan probe orderings.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, cast
from unittest.mock import patch

import pytest
import pytest_asyncio
import structlog
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from structlog.stdlib import AsyncBoundLogger

from gubbi_common.bootstrap import (
    ProbeFailure,
    ProbeOutcome,
    ProbeResult,
    ProbeStatus,
    StartupBudgetExceeded,
    StartupRunner,
)

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


_PROBE_BEHAVIOR = Callable[["FakeProbe"], Awaitable[ProbeResult]]


@dataclass
class FakeProbe:
    """Test double for the StartupProbe Protocol.

    ``behavior`` is the swappable ``run()`` body; the default is an
    immediate OK. The runner stamps ``_probe_logger`` on this instance
    just before invoking ``run()`` -- ``behavior`` can read it via
    ``probe._probe_logger`` to emit captured log events.
    """

    name: str = "fake"
    required: bool = True
    timeout_s: float = 5.0
    behavior: _PROBE_BEHAVIOR = field(
        default_factory=lambda: _ok_behavior  # type: ignore[arg-type]
    )
    invoked: int = 0

    async def run(self) -> ProbeResult:
        self.invoked += 1
        return await self.behavior(self)


async def _ok_behavior(_probe: FakeProbe) -> ProbeResult:
    return ProbeResult(status=ProbeStatus.OK)


def _configure_structlog_for_capture() -> None:
    """Reset structlog to a deterministic JSON renderer at the chain tail.

    The runner's ``_build_probe_logger`` injects the deque tap just
    before the final processor; placing a JSONRenderer last lets us
    confirm the tap captures the dict form (not the rendered string).
    """
    structlog.reset_defaults()
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=AsyncBoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


@pytest_asyncio.fixture
async def logger() -> AsyncIterator[AsyncBoundLogger]:
    """Yield an AsyncBoundLogger and reset structlog defaults on teardown.

    The fixture mutates the structlog global config so the runner's
    tap-processor injection has a deterministic chain to splice into;
    ``reset_defaults`` on teardown prevents that mutation from bleeding
    into other test modules (e.g. tests/telemetry that exercise the
    sync ``BoundLogger`` default).
    """
    _configure_structlog_for_capture()
    try:
        yield cast("AsyncBoundLogger", structlog.get_logger("test")).bind()
    finally:
        structlog.reset_defaults()


@pytest.fixture
def in_memory_exporter() -> Iterator[InMemorySpanExporter]:
    """Install an in-memory OTel exporter on a fresh TracerProvider.

    The OTel API only allows ``set_tracer_provider`` to be called once
    per process. We forcibly reset the once-flag so each test installs
    its own SDK provider; without this, spans from earlier tests would
    leak into later assertions and the second ``set_tracer_provider``
    call would be silently dropped with a warning.

    The runner's ``get_tracer()`` resolves the global tracer at call
    time, so installing a provider here causes the runner's spans to
    land in this exporter for assertion. The previous provider state
    is captured + restored on teardown so this fixture cannot bleed
    OTel state into subsequent test modules.
    """
    # Reset the OTel global tracer provider state. Both attribute names
    # and the ``Once`` flag are private but stable in 1.29.x; we re-assert
    # them on every test to keep span emission deterministic.
    from opentelemetry.trace import _TRACER_PROVIDER_SET_ONCE

    original_provider = trace._TRACER_PROVIDER  # type: ignore[attr-defined]
    original_done = _TRACER_PROVIDER_SET_ONCE._done  # type: ignore[attr-defined]
    _TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
    trace._TRACER_PROVIDER = None  # type: ignore[attr-defined]

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    try:
        yield exporter
    finally:
        # Restore prior provider state for subsequent tests.
        provider.shutdown()
        trace._TRACER_PROVIDER = original_provider  # type: ignore[attr-defined]
        _TRACER_PROVIDER_SET_ONCE._done = original_done  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_happy_path_three_ok_probes(
    logger: AsyncBoundLogger,
    in_memory_exporter: InMemorySpanExporter,
) -> None:
    # Arrange
    probes = [
        FakeProbe(name="alpha", behavior=_ok_behavior),
        FakeProbe(name="beta", behavior=_ok_behavior),
        FakeProbe(name="gamma", behavior=_ok_behavior),
    ]
    runner = StartupRunner(app_env="test")

    # Act
    outcomes = await runner.run(probes, logger=logger)

    # Assert
    assert [o.name for o in outcomes] == ["alpha", "beta", "gamma"]
    assert all(o.status is ProbeStatus.OK for o in outcomes)
    # OK -> log_tail discarded.
    assert all(o.log_tail == () for o in outcomes)
    # All three probes invoked exactly once.
    assert all(p.invoked == 1 for p in probes)
    # Three spans emitted, all with outcome=ok.
    spans = in_memory_exporter.get_finished_spans()
    assert [s.name for s in spans] == [
        "startup.probe.alpha",
        "startup.probe.beta",
        "startup.probe.gamma",
    ]
    for span in spans:
        attrs = dict(span.attributes or {})
        assert attrs["probe.outcome"] == "ok"
        assert attrs["probe.timed_out"] is False


# ---------------------------------------------------------------------------
# 2. Required FAIL raises ProbeFailure
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_required_fail_raises_probe_failure(
    logger: AsyncBoundLogger,
    in_memory_exporter: InMemorySpanExporter,
) -> None:
    async def _fail(_probe: FakeProbe) -> ProbeResult:
        return ProbeResult(status=ProbeStatus.FAIL, diagnostic={"why": "boom"})

    probes = [
        FakeProbe(name="alpha", behavior=_ok_behavior),
        FakeProbe(name="beta", required=True, behavior=_fail),
        FakeProbe(name="gamma", behavior=_ok_behavior),
    ]
    runner = StartupRunner(app_env="test")

    with pytest.raises(ProbeFailure) as excinfo:
        await runner.run(probes, logger=logger)

    outcome = excinfo.value.outcome
    assert outcome.name == "beta"
    assert outcome.status is ProbeStatus.FAIL
    assert outcome.diagnostic == {"why": "boom"}
    # Probes after the failed one are NOT invoked.
    assert probes[0].invoked == 1
    assert probes[1].invoked == 1
    assert probes[2].invoked == 0


# ---------------------------------------------------------------------------
# 3. Non-required FAIL becomes WARN counter
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_non_required_fail_continues_with_counter(
    logger: AsyncBoundLogger,
) -> None:
    async def _fail(_probe: FakeProbe) -> ProbeResult:
        return ProbeResult(status=ProbeStatus.FAIL)

    probes = [
        FakeProbe(name="alpha", required=False, behavior=_fail),
        FakeProbe(name="beta", required=True, behavior=_ok_behavior),
    ]
    counter_calls: list[Mapping[str, Any]] = []

    def _counter(**kwargs: Any) -> None:
        counter_calls.append(kwargs)

    runner = StartupRunner(app_env="test", outcome_counter=_counter)

    outcomes = await runner.run(probes, logger=logger)

    # Raw outcome.status stays FAIL for the lifespan caller's
    # inspection (truth-telling): "the probe ran and returned FAIL".
    assert outcomes[0].name == "alpha"
    assert outcomes[0].status is ProbeStatus.FAIL
    assert outcomes[1].name == "beta"
    assert outcomes[1].status is ProbeStatus.OK
    # Observability counter sees the DOWNGRADED outcome -- non-required
    # FAIL is reported as "warn" to the counter / span / log rails.
    assert counter_calls[0] == {
        "name": "alpha",
        "outcome": "warn",
        "app_env": "test",
    }
    assert counter_calls[1] == {
        "name": "beta",
        "outcome": "ok",
        "app_env": "test",
    }


# ---------------------------------------------------------------------------
# 4. Per-probe timeout
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_per_probe_timeout_raises_for_required(
    logger: AsyncBoundLogger,
    in_memory_exporter: InMemorySpanExporter,
) -> None:
    async def _slow(_probe: FakeProbe) -> ProbeResult:
        await asyncio.sleep(5)
        return ProbeResult(status=ProbeStatus.OK)  # pragma: no cover

    probes = [FakeProbe(name="slow", required=True, timeout_s=0.05, behavior=_slow)]
    runner = StartupRunner(app_env="test")

    with pytest.raises(ProbeFailure) as excinfo:
        await runner.run(probes, logger=logger)

    outcome = excinfo.value.outcome
    assert outcome.timed_out is True
    assert outcome.status is ProbeStatus.FAIL
    assert outcome.error_type == "TimeoutError"
    assert outcome.diagnostic == {"timeout_s": 0.05}
    # Span attribute mirrors the timed_out flag.
    spans = in_memory_exporter.get_finished_spans()
    attrs = dict(spans[0].attributes or {})
    assert attrs["probe.timed_out"] is True
    assert attrs["probe.outcome"] == "fail"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_timeout_non_required_does_not_raise(
    logger: AsyncBoundLogger,
    in_memory_exporter: InMemorySpanExporter,
) -> None:
    async def _slow(_probe: FakeProbe) -> ProbeResult:
        await asyncio.sleep(5)
        return ProbeResult(status=ProbeStatus.OK)  # pragma: no cover

    probes = [
        FakeProbe(name="slow", required=False, timeout_s=0.05, behavior=_slow),
    ]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)
    # Raw status stays FAIL for the lifespan caller's inspection.
    assert outcomes[0].timed_out is True
    assert outcomes[0].status is ProbeStatus.FAIL
    # Observability outcome on the span is downgraded to "warn".
    spans = in_memory_exporter.get_finished_spans()
    attrs = dict(spans[0].attributes or {})
    assert attrs["probe.outcome"] == "warn"
    assert attrs["probe.timed_out"] is True


# ---------------------------------------------------------------------------
# 5. Total budget exceeded
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_total_budget_exceeded_before_third_probe(
    logger: AsyncBoundLogger,
) -> None:
    """The budget is checked at the TOP of each iteration; gamma is never started.

    Use a patched ``monotonic`` so the test does not depend on real
    wall-clock progression -- avoids CI flake when sleep slips.
    """

    async def _ok(_probe: FakeProbe) -> ProbeResult:
        return ProbeResult(status=ProbeStatus.OK)

    probes = [
        FakeProbe(name="alpha", behavior=_ok),
        FakeProbe(name="beta", behavior=_ok),
        FakeProbe(name="gamma", behavior=_ok),
    ]
    runner = StartupRunner(app_env="test", total_budget_s=0.7)

    # Yield monotonically advancing values so the runner's
    # cumulative-time check trips before gamma. Sequence covers the
    # start_total reading + each probe's pre-iteration check + each
    # probe's t0 + the post-run delta. Falls back to a large value
    # once the script is exhausted.
    fake_times = iter(
        [
            0.0,  # start_total
            0.0,  # iter 1 (alpha) budget check
            0.1,  # iter 1 (alpha) t0
            0.2,  # iter 1 (alpha) duration calc
            0.3,  # iter 2 (beta) budget check
            0.4,  # iter 2 (beta) t0
            0.5,  # iter 2 (beta) duration calc
            10.0,  # iter 3 (gamma) budget check -- now exceeds 0.7
        ]
    )

    def _fake_monotonic() -> float:
        try:
            return next(fake_times)
        except StopIteration:
            return 100.0  # large sentinel; budget already exceeded

    with (
        patch("gubbi_common.bootstrap.probe_runner.monotonic", _fake_monotonic),
        pytest.raises(StartupBudgetExceeded) as excinfo,
    ):
        await runner.run(probes, logger=logger)

    # Budget guard runs before probe 3 (gamma) is invoked.
    assert excinfo.value.name == "gamma"
    assert excinfo.value.budget_s == 0.7
    assert probes[0].invoked == 1
    assert probes[1].invoked == 1
    assert probes[2].invoked == 0


# ---------------------------------------------------------------------------
# 6. Deque tap captures last 50 records on FAIL
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_deque_tap_keeps_last_50_on_fail(
    logger: AsyncBoundLogger,
) -> None:
    async def _emit_then_fail(probe: FakeProbe) -> ProbeResult:
        log = probe._probe_logger  # type: ignore[attr-defined]
        for i in range(60):
            await log.info("tick", step=i, value=f"v{i}")
        return ProbeResult(status=ProbeStatus.FAIL)

    probes = [FakeProbe(name="chatty", required=False, behavior=_emit_then_fail)]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)

    tail = outcomes[0].log_tail
    assert len(tail) == 50
    # Oldest 10 (steps 0-9) dropped; tail starts at step 10 and ends at 59.
    assert tail[0]["step"] == 10
    assert tail[-1]["step"] == 59
    # Structured fields preserved -- we got a dict, not a JSON string.
    assert tail[0]["event"] == "tick"
    assert tail[0]["probe"] == "chatty"
    assert tail[5]["value"] == f"v{15}"


# ---------------------------------------------------------------------------
# 7. OK discards tail
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ok_discards_log_tail(
    logger: AsyncBoundLogger,
) -> None:
    async def _emit_then_ok(probe: FakeProbe) -> ProbeResult:
        log = probe._probe_logger  # type: ignore[attr-defined]
        for i in range(5):
            await log.info("ping", i=i)
        return ProbeResult(status=ProbeStatus.OK)

    probes = [FakeProbe(name="quiet", behavior=_emit_then_ok)]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)

    assert outcomes[0].status is ProbeStatus.OK
    assert outcomes[0].log_tail == ()


# ---------------------------------------------------------------------------
# 8. OTel attributes set on span
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_otel_attributes_present_on_span(
    logger: AsyncBoundLogger,
    in_memory_exporter: InMemorySpanExporter,
) -> None:
    probes = [FakeProbe(name="alpha", required=False, behavior=_ok_behavior)]
    runner = StartupRunner(app_env="test")

    await runner.run(probes, logger=logger)

    spans = in_memory_exporter.get_finished_spans()
    assert len(spans) == 1
    attrs = dict(spans[0].attributes or {})
    assert attrs["probe.required"] is False
    assert attrs["probe.outcome"] == "ok"
    assert attrs["probe.timed_out"] is False
    # duration_ms >= 0 (non-negative finite float).
    assert isinstance(attrs["probe.duration_ms"], float)
    assert attrs["probe.duration_ms"] >= 0.0


# ---------------------------------------------------------------------------
# 9. NoOp tracer fallback
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_runner_with_noop_tracer_completes(
    logger: AsyncBoundLogger,
) -> None:
    """When no SDK provider is installed, get_tracer() returns a NoOp tracer.

    The runner must still complete and return outcomes; spans are
    silently absorbed. Saved + restored OTel state on teardown so this
    test cannot bleed a NoOp provider into subsequent test modules.
    """
    # Force a NoOp tracer provider; this is the documented "off" position
    # for OTel and exercises the runner's NoOp-safe span path.
    from opentelemetry.trace import _TRACER_PROVIDER_SET_ONCE, NoOpTracerProvider

    original_provider = trace._TRACER_PROVIDER  # type: ignore[attr-defined]
    original_done = _TRACER_PROVIDER_SET_ONCE._done  # type: ignore[attr-defined]
    _TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
    trace._TRACER_PROVIDER = None  # type: ignore[attr-defined]
    trace.set_tracer_provider(NoOpTracerProvider())
    try:
        probes = [FakeProbe(name="alpha", behavior=_ok_behavior)]
        runner = StartupRunner(app_env="test")

        outcomes = await runner.run(probes, logger=logger)
        assert outcomes[0].status is ProbeStatus.OK
    finally:
        trace._TRACER_PROVIDER = original_provider  # type: ignore[attr-defined]
        _TRACER_PROVIDER_SET_ONCE._done = original_done  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 10. outcome_counter hook
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_outcome_counter_fires_for_every_probe(
    logger: AsyncBoundLogger,
) -> None:
    async def _warn(_probe: FakeProbe) -> ProbeResult:
        return ProbeResult(status=ProbeStatus.WARN)

    async def _fail_nonreq(_probe: FakeProbe) -> ProbeResult:
        return ProbeResult(status=ProbeStatus.FAIL)

    probes = [
        FakeProbe(name="alpha", behavior=_ok_behavior),
        FakeProbe(name="beta", behavior=_warn),
        FakeProbe(name="gamma", required=False, behavior=_fail_nonreq),
    ]
    seen: list[Mapping[str, Any]] = []
    runner = StartupRunner(
        app_env="prod",
        outcome_counter=lambda **kw: seen.append(kw),
    )

    await runner.run(probes, logger=logger)

    # gamma is non-required FAIL -> downgraded to WARN on the counter.
    assert seen == [
        {"name": "alpha", "outcome": "ok", "app_env": "prod"},
        {"name": "beta", "outcome": "warn", "app_env": "prod"},
        {"name": "gamma", "outcome": "warn", "app_env": "prod"},
    ]


# ---------------------------------------------------------------------------
# 11. Probe-internal exception
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_internal_exception_caught(
    logger: AsyncBoundLogger,
) -> None:
    async def _explode(_probe: FakeProbe) -> ProbeResult:
        raise ValueError("the database said no")

    probes = [FakeProbe(name="bad", required=True, behavior=_explode)]
    runner = StartupRunner(app_env="test")

    with pytest.raises(ProbeFailure) as excinfo:
        await runner.run(probes, logger=logger)

    outcome = excinfo.value.outcome
    assert outcome.status is ProbeStatus.FAIL
    assert outcome.error_type == "ValueError"
    assert outcome.error_message == "the database said no"
    assert outcome.timed_out is False


# ---------------------------------------------------------------------------
# 12. Diagnostic round-trips
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_diagnostic_round_trips(
    logger: AsyncBoundLogger,
) -> None:
    """The runner does NOT redact diagnostic; probe-author owns that contract."""
    diag = {"foo": "bar", "depth": 2, "nested": {"k": "v"}}

    async def _emit(_probe: FakeProbe) -> ProbeResult:
        return ProbeResult(status=ProbeStatus.WARN, diagnostic=diag)

    probes = [FakeProbe(name="diag", required=False, behavior=_emit)]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)

    assert dict(outcomes[0].diagnostic) == diag


# ---------------------------------------------------------------------------
# Bonus: ProbeOutcome construction sanity (defensive contract pin)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_probe_outcome_is_frozen_dataclass() -> None:
    outcome = ProbeOutcome(
        name="x",
        required=True,
        status=ProbeStatus.OK,
        duration_ms=1.5,
        timed_out=False,
        diagnostic={},
        log_tail=(),
        error_type=None,
        error_message=None,
    )
    # Frozen dataclasses raise FrozenInstanceError (subclass of
    # AttributeError) on attribute assignment; pin the precise type.
    with pytest.raises(AttributeError):
        outcome.duration_ms = 99.9  # type: ignore[misc]


@pytest.mark.unit
def test_probe_status_string_values() -> None:
    assert ProbeStatus.OK.value == "ok"
    assert ProbeStatus.WARN.value == "warn"
    assert ProbeStatus.FAIL.value == "fail"


# ---------------------------------------------------------------------------
# 13. Empty probe list
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_run_with_empty_probe_list_returns_empty_tuple(
    logger: AsyncBoundLogger,
) -> None:
    runner = StartupRunner(app_env="ci")
    result = await runner.run([], logger=logger)
    assert result == ()


# ---------------------------------------------------------------------------
# 14. WARN status preserves log_tail content emitted via _probe_logger
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_warn_status_log_tail_reflects_probe_logger_emissions(
    logger: AsyncBoundLogger,
) -> None:
    """Probe emits via self._probe_logger then returns WARN; tail captures all events."""

    async def _emit_then_warn(probe: FakeProbe) -> ProbeResult:
        log = probe._probe_logger  # type: ignore[attr-defined]
        await log.debug("zeroth", step=0)
        await log.info("first", step=1)
        await log.warning("second", step=2, severity="medium")
        await log.error("third", step=3, severity="high")
        return ProbeResult(status=ProbeStatus.WARN, diagnostic={"reason": "degraded"})

    probes = [FakeProbe(name="degrading", required=False, behavior=_emit_then_warn)]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)

    assert outcomes[0].status is ProbeStatus.WARN
    tail = outcomes[0].log_tail
    assert len(tail) == 4
    assert tail[0]["event"] == "zeroth"
    assert tail[0]["level"] == "debug"
    assert tail[0]["step"] == 0
    assert tail[1]["event"] == "first"
    assert tail[1]["level"] == "info"
    assert tail[1]["step"] == 1
    assert tail[2]["event"] == "second"
    assert tail[2]["level"] == "warning"
    assert tail[2]["severity"] == "medium"
    assert tail[3]["event"] == "third"
    assert tail[3]["level"] == "error"
    assert tail[3]["severity"] == "high"
    # All entries carry the probe-name binding.
    for entry in tail:
        assert entry["probe"] == "degrading"


# ---------------------------------------------------------------------------
# 15. Non-required FAIL emits "fail" event but observability-warns
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_non_required_fail_observability_outcome_is_warn(
    logger: AsyncBoundLogger,
    in_memory_exporter: InMemorySpanExporter,
) -> None:
    """H3 contract: non-required FAIL keeps status=FAIL but observability=WARN."""

    async def _fail(_probe: FakeProbe) -> ProbeResult:
        return ProbeResult(status=ProbeStatus.FAIL, diagnostic={"why": "no quorum"})

    probes = [FakeProbe(name="optional", required=False, behavior=_fail)]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)

    # Truth-telling: raw status stays FAIL.
    assert outcomes[0].status is ProbeStatus.FAIL
    # Observability: span attribute reflects WARN downgrade.
    spans = in_memory_exporter.get_finished_spans()
    attrs = dict(spans[0].attributes or {})
    assert attrs["probe.outcome"] == "warn"


# ---------------------------------------------------------------------------
# 16. Outcome counter callback that raises does not abort the boot
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_outcome_counter_exception_does_not_abort_run(
    logger: AsyncBoundLogger,
) -> None:
    """M5 contract: counter bug must not abort boot."""

    def _exploding_counter(*, name: str, outcome: str, app_env: str) -> None:
        del name, outcome, app_env
        raise RuntimeError("counter blew up")

    probes = [
        FakeProbe(name="alpha", behavior=_ok_behavior),
        FakeProbe(name="beta", behavior=_ok_behavior),
    ]
    runner = StartupRunner(app_env="test", outcome_counter=_exploding_counter)

    # Both probes complete normally; the runner swallows the counter
    # exception via warning log + continues.
    outcomes = await runner.run(probes, logger=logger)
    assert len(outcomes) == 2
    assert all(o.status is ProbeStatus.OK for o in outcomes)


# ---------------------------------------------------------------------------
# 17. Error message is scrubbed of URL credentials
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_error_message_scrubs_url_credentials(
    logger: AsyncBoundLogger,
) -> None:
    """M6 contract: scheme://user:pass@host -> scheme://***@host in error_message."""

    async def _explode(_probe: FakeProbe) -> ProbeResult:
        raise ConnectionError(
            "could not connect to postgres://leaky_user:supersecret@db.internal:5432/app"
        )

    probes = [FakeProbe(name="bad", required=False, behavior=_explode)]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)

    assert outcomes[0].status is ProbeStatus.FAIL
    assert outcomes[0].error_type == "ConnectionError"
    msg = outcomes[0].error_message
    assert msg is not None
    # Password component masked, host component preserved.
    assert "supersecret" not in msg
    assert "leaky_user" not in msg
    assert "***@db.internal" in msg


# ---------------------------------------------------------------------------
# 18. Deep-copy snapshot insulation: probe mutates kwargs after the call
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_log_tail_snapshot_alias_insulated_from_post_call_mutation(
    logger: AsyncBoundLogger,
) -> None:
    """Deep-copy at snapshot time insulates the captured tail from later
    mutation of the original kwargs payload.

    Scope note: this test asserts ALIAS-INSULATION only -- that mutating
    the source dict after the call does not propagate into the captured
    snapshot. It does NOT assert deep immutability of the captured
    snapshot itself; ``MappingProxyType`` is a shallow freeze, so
    nested dicts/lists inside a captured payload remain mutable in
    principle. The contract pinned here is "post-call mutation can't
    leak back into log_tail", not "log_tail entries are
    transitively immutable".
    """

    async def _emit_then_mutate_then_fail(probe: FakeProbe) -> ProbeResult:
        log = probe._probe_logger  # type: ignore[attr-defined]
        payload = {"items": [1, 2, 3], "depth": 1}
        await log.info("snapshot", payload=payload)
        # Mutate after the call -- captured snapshot must not see this.
        payload["items"].append(99)
        payload["depth"] = 999
        return ProbeResult(status=ProbeStatus.FAIL)

    probes = [
        FakeProbe(name="mutator", required=False, behavior=_emit_then_mutate_then_fail),
    ]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)

    tail = outcomes[0].log_tail
    assert len(tail) == 1
    captured = tail[0]
    assert captured["payload"] == {"items": [1, 2, 3], "depth": 1}


# ---------------------------------------------------------------------------
# 19. _ProbeTapLogger supports critical() and exception()
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_probe_tap_logger_supports_exception_and_critical(
    logger: AsyncBoundLogger,
) -> None:
    """H1 contract: ``_ProbeTapLogger`` exposes ``critical()`` and ``exception()``.

    Probes calling these methods through ``self._probe_logger`` must not
    raise ``AttributeError`` (which the runner would otherwise catch as
    a probe FAIL with ``error_type="AttributeError"``). The snapshot
    must capture the level + event + per-call kwargs into ``log_tail``.
    """

    async def _emit_critical_and_exception(probe: FakeProbe) -> ProbeResult:
        log = probe._probe_logger  # type: ignore[attr-defined]
        await log.critical("crit_event", code="EFAIL", severity="critical")
        # structlog's ``exception()`` typically auto-attaches ``exc_info``
        # from the current except scope on the wrapped logger's emit;
        # the wrapper's snapshot captures the explicit kwargs only, so
        # this test asserts the kwarg path lands in log_tail.
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            await log.exception("exc_event", reason="boom")
        return ProbeResult(status=ProbeStatus.FAIL)

    probes = [FakeProbe(name="leveler", required=False, behavior=_emit_critical_and_exception)]
    runner = StartupRunner(app_env="test")

    outcomes = await runner.run(probes, logger=logger)

    tail = outcomes[0].log_tail
    assert len(tail) == 2

    crit = tail[0]
    assert crit["event"] == "crit_event"
    assert crit["level"] == "critical"
    assert crit["probe"] == "leveler"
    assert crit["code"] == "EFAIL"
    assert crit["severity"] == "critical"

    exc = tail[1]
    assert exc["event"] == "exc_event"
    assert exc["level"] == "exception"
    assert exc["probe"] == "leveler"
    assert exc["reason"] == "boom"


# ---------------------------------------------------------------------------
# 20. Counter-callback exception message scrubbed of URL credentials
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_outcome_counter_exception_message_is_scrubbed(
    logger: AsyncBoundLogger,
) -> None:
    """L2 contract: counter-failure log path scrubs URL credentials.

    The runner's counter-failure ``logger.warning`` call routes the
    exception's ``str(exc)`` through ``_scrub_error_message``. This
    test pins the MASKING correctness of that path. The companion
    ``test_outcome_counter_exception_does_not_abort_run`` covers only
    the FLOW (boot continues despite the counter raising); it raises
    a credential-free ``RuntimeError`` so the regex never fires.
    """
    from structlog.testing import capture_logs

    def _exploding_counter(*, name: str, outcome: str, app_env: str) -> None:
        del name, outcome, app_env
        raise ConnectionError(
            "could not connect to postgres://leaky:supersecret@db.internal:5432/foo"
        )

    probes = [FakeProbe(name="alpha", behavior=_ok_behavior)]
    runner = StartupRunner(app_env="test", outcome_counter=_exploding_counter)

    with capture_logs() as captured:
        await runner.run(probes, logger=logger)

    counter_failure = next(
        (
            entry
            for entry in captured
            if entry.get("event") == "startup.probe.counter_callback_failed"
        ),
        None,
    )
    assert counter_failure is not None
    assert counter_failure.get("error_type") == "ConnectionError"
    msg = counter_failure.get("error_message")
    assert msg is not None
    # Password component masked, host component preserved.
    assert "supersecret" not in msg
    assert "leaky" not in msg
    assert "***@db.internal" in msg
