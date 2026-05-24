"""Protocol + Runner for app startup probes.

Provides StartupProbe (a runtime-checkable Protocol consumers implement),
ProbeStatus / ProbeResult / ProbeOutcome dataclasses, and StartupRunner
which orchestrates probes with timeout enforcement, OTel span emission,
probe-scoped log-tail capture, and a deterministic failure log shape.

Cross-app contract: gubbi + gubbi-cloud + extraction worker all consume
this Protocol so their lifespan probe orderings are structurally
verifiable. Runner stays free of framework deps and intentionally tight.

Probes MUST NOT mutate the global tracer/meter provider; doing so
breaks the OTel span ordering across boot.

Probes that want events folded into the FAIL/WARN ``log_tail`` should
emit through ``self._probe_logger`` -- the runner stamps a tap-bound
wrapper logger onto each probe instance just before invoking
``probe.run()``. Probes that don't need captured logging simply ignore
the attribute; the runner never inspects it afterwards.

Probes MUST NOT log secrets via ``self._probe_logger``. Events emitted
through the probe-scoped logger are captured in a 50-deep ring buffer
and, on FAIL/WARN, surfaced as the ``log_tail`` field of the runner's
structured event -- which ships to whatever sink the consumer's
``logger`` is wired to (typically HyperDX or a structured-log sink).
The runner does NOT scrub log_tail entries; the contract is
probe-author-side.
"""

from __future__ import annotations

import asyncio
import copy
import re
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from gubbi_common.telemetry.otel import get_tracer

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from structlog.stdlib import AsyncBoundLogger

__all__ = [
    "OutcomeCounterCallback",
    "ProbeFailure",
    "ProbeOutcome",
    "ProbeResult",
    "ProbeStatus",
    "StartupBudgetExceeded",
    "StartupProbe",
    "StartupRunner",
]


class ProbeStatus(StrEnum):
    """Lifecycle outcome for a single startup probe.

    ``OK`` -- probe completed cleanly.
    ``WARN`` -- probe completed with degraded but non-fatal state.
    ``FAIL`` -- probe failed. For required probes this aborts boot; for
    non-required probes the runner downgrades the observability outcome
    (counter / span / structured-log emission) to ``WARN`` while keeping
    the raw status as ``FAIL`` on the returned ``ProbeOutcome``.
    """

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


_EMPTY_DIAGNOSTIC: Mapping[str, Any] = MappingProxyType({})

# Cap on the per-probe ring buffer of structured events feeding ``log_tail``.
# 50 entries is enough to recover a recent failure narrative without
# unbounded memory growth on a probe that emits chattily before failing.
_LOG_TAIL_MAXLEN: int = 50

# URL credential pattern used by ``_scrub_error_message``. Defense-in-depth
# scrubber for driver exceptions that echo connection URLs verbatim.
_URL_CRED_RE = re.compile(r"(\w+://)([^/@\s]+):[^@\s]+@")


def _scrub_error_message(msg: str) -> str:
    """Strip URL credentials of the form ``scheme://user:pass@host``.

    Defense-in-depth: probe authors should not emit credentials in
    exception messages, but driver exceptions sometimes echo connection
    URLs verbatim. Mask the password component before the message
    enters structured logs / OTel attrs.
    """
    return _URL_CRED_RE.sub(r"\1***@", msg)


@dataclass(frozen=True)
class ProbeResult:
    """Probe-author-supplied outcome.

    ``diagnostic`` is exposed in structured logs; do NOT place secrets,
    tokens, or credentials here. (Diagnostic is NOT mirrored onto OTel
    span attrs -- only ``probe.required``, ``probe.duration_ms``,
    ``probe.outcome``, and ``probe.timed_out`` ride the span.)
    """

    status: ProbeStatus
    diagnostic: Mapping[str, Any] = field(default_factory=lambda: _EMPTY_DIAGNOSTIC)


@dataclass(frozen=True)
class ProbeOutcome:
    """Outcome of a probe execution.

    Constructed only by ``StartupRunner.run()``. Consumer code reads
    fields (e.g. ``outcome.status``, ``outcome.log_tail``,
    ``outcome.diagnostic``) via the tuple returned by ``run()`` or via
    ``ProbeFailure.outcome``. Probes that need to surface a value back
    to the lifespan body store it on the probe instance, NOT on the
    outcome (see runner class docstring for the pattern).

    ``status`` is the RAW status the probe returned (or ``FAIL`` when
    the probe raised / timed out). The runner emits observability
    signals (counter, span attribute, structured log level) using a
    DOWNGRADED outcome where non-required ``FAIL`` becomes ``WARN``;
    ``status`` here is left untouched so the lifespan caller can still
    distinguish "probe ran, returned ``FAIL``" from "probe ran,
    returned ``WARN``".

    ``log_tail`` is the per-probe ring-buffer (max 50) of probe-emitted
    log events captured pre-processor. See ``_ProbeTapLogger`` docstring
    for the scope caveat: bound context (``correlation_id``) +
    processor output (timestamp, rendered fields) live in the consumer's
    log sink, not here.
    """

    name: str
    required: bool
    status: ProbeStatus
    duration_ms: float
    timed_out: bool
    diagnostic: Mapping[str, Any]
    log_tail: tuple[Mapping[str, Any], ...]
    error_type: str | None
    error_message: str | None


@runtime_checkable
class StartupProbe(Protocol):
    """Contract a startup probe must implement.

    Three required attributes plus an async ``run()`` returning
    ``ProbeResult``. The runner enforces the per-probe ``timeout_s`` and
    treats ``required=False`` probes as warn-only on FAIL: the raw
    ``ProbeOutcome.status`` stays ``FAIL`` for the lifespan caller, but
    the runner's observability signals (counter, span attribute,
    structured log level) downgrade to ``WARN``.

    Probe authors are responsible for keeping events emitted via
    ``self._probe_logger`` free of credentials. The runner forwards
    ``log_tail`` to the consumer's structured-log sink without
    scrubbing.
    """

    name: str
    required: bool
    timeout_s: float

    async def run(self) -> ProbeResult:
        """Execute the probe; return its ``ProbeResult`` outcome."""
        ...


class OutcomeCounterCallback(Protocol):
    """Callback signature for probe outcome instrumentation.

    Called once per probe with the observability outcome (after the
    non-required FAIL -> WARN downgrade). Implementations MUST NOT
    raise; the runner catches and logs to avoid aborting the boot
    on a counter bug.
    """

    def __call__(self, *, name: str, outcome: str, app_env: str) -> None:
        """Record a probe outcome at the consumer's preferred sink."""
        ...


class ProbeFailure(RuntimeError):
    """Raised by StartupRunner when a required probe returns FAIL or raises.

    Carries the ProbeOutcome for the lifespan caller to log/inspect
    before tearing down resources.
    """

    def __init__(self, outcome: ProbeOutcome) -> None:
        super().__init__(
            f"required startup probe failed: name={outcome.name} "
            f"status={outcome.status.value} duration_ms={outcome.duration_ms:.1f} "
            f"error_type={outcome.error_type} error_message={outcome.error_message}"
        )
        self.outcome = outcome


class StartupBudgetExceeded(RuntimeError):
    """Raised when the soft pre-flight budget is exceeded between probes.

    The budget is checked at the TOP of each probe iteration; it is NOT
    a wall-clock cap on individual probes. A probe that starts within
    budget can still run a full ``probe.timeout_s`` past the budget
    line. To enforce a hard wall-clock cap, set per-probe ``timeout_s``
    such that the sum bounds your acceptable boot time.
    """

    def __init__(self, name: str, budget_s: float) -> None:
        super().__init__(f"startup budget exceeded before probe {name!r} (budget_s={budget_s})")
        self.name = name
        self.budget_s = budget_s


class _ProbeTapLogger:
    """Probe-scoped logger that taps emissions into a deque + delegates.

    Wraps the consumer's structlog ``AsyncBoundLogger``. Each call
    records a snapshot dict ``{event, level, probe, **kwargs}`` into
    the runner's deque (deep-copied + frozen via ``MappingProxyType``
    to insulate the captured tail from later mutation), then delegates
    to the wrapped logger so emissions still ship through the
    consumer's full processor chain.

    Supported methods (snapshot + delegate):

    - ``debug``, ``info``, ``warning``, ``error``, ``critical``,
      ``exception``

    Not supported (probes calling these raise ``AttributeError``, which
    the runner catches as a probe FAIL):

    - ``bind`` / ``unbind`` / ``new`` -- return new logger instances;
      don't fit the wrapper model. Probes that need a sub-logger should
      call the base logger directly.
    - ``log(level, ...)`` -- generic level dispatch; use one of the
      named levels above.
    - ``warn`` -- deprecated alias for ``warning``; not exposed.

    Probes that emit through ``self._probe_logger`` fold their events
    into the runner's ``log_tail`` diagnostic on FAIL/WARN. Probes that
    ignore the attribute simply don't contribute to ``log_tail``.

    log_tail capture scope: the snapshot reflects the probe's KWARG
    emissions (event + level + per-call kwargs), NOT post-processor
    structured events. Logger-bound context (correlation_id, etc.) and
    processor-added fields (timestamp, render output) appear in the
    consumer's log sink but NOT in log_tail. For full forensic context,
    correlate by ``probe`` name + timestamp range against the
    consumer's structured-log sink.

    Method names mirror ``AsyncBoundLogger``'s async logging surface
    (``info`` / ``warning`` / ``error`` / ``debug`` / ``critical`` /
    ``exception`` are all coroutines). No structlog internals (no
    ``sync_bl``, no ``_processors``) are touched -- the wrapper
    survives structlog minor-version bumps.
    """

    def __init__(
        self,
        base: AsyncBoundLogger,
        tap: deque[Mapping[str, Any]],
        probe_name: str,
    ) -> None:
        self._base = base
        self._tap = tap
        self._probe_name = probe_name

    async def debug(self, event: str, **kwargs: Any) -> None:
        self._snapshot("debug", event, kwargs)
        await self._base.debug(event, **kwargs)

    async def info(self, event: str, **kwargs: Any) -> None:
        self._snapshot("info", event, kwargs)
        await self._base.info(event, **kwargs)

    async def warning(self, event: str, **kwargs: Any) -> None:
        self._snapshot("warning", event, kwargs)
        await self._base.warning(event, **kwargs)

    async def error(self, event: str, **kwargs: Any) -> None:
        self._snapshot("error", event, kwargs)
        await self._base.error(event, **kwargs)

    async def critical(self, event: str, **kwargs: Any) -> None:
        self._snapshot("critical", event, kwargs)
        await self._base.critical(event, **kwargs)

    async def exception(self, event: str, **kwargs: Any) -> None:
        # NOTE: ``exception()`` typically auto-attaches traceback context
        # via the ``logging.exc_info`` hook on the wrapped logger's
        # processor chain. The snapshot captures the explicit kwargs
        # only; tracebacks land in the wrapped logger's emit per its
        # config, not in ``log_tail``.
        self._snapshot("exception", event, kwargs)
        await self._base.exception(event, **kwargs)

    def _snapshot(self, level: str, event: str, kwargs: Mapping[str, Any]) -> None:
        # Deep copy so probes can mutate kwargs after the call without
        # corrupting the captured snapshot. Wrap in MappingProxyType so
        # consumers iterating the tail can't mutate captured entries.
        snapshot = copy.deepcopy(
            {"event": event, "level": level, "probe": self._probe_name, **dict(kwargs)}
        )
        self._tap.append(MappingProxyType(snapshot))


class StartupRunner:
    """Orchestrate a sequence of startup probes with timeouts + tail capture.

    Per-probe semantics:

    * Each probe gets its own OTel span ``startup.probe.<name>`` carrying
      ``probe.required``, ``probe.duration_ms``, ``probe.outcome``, and
      ``probe.timed_out`` attributes.
    * Per-probe ``timeout_s`` is enforced with ``asyncio.timeout``.
    * Probe-internal exceptions are caught and reported as FAIL with
      ``error_type`` / ``error_message`` populated. Required FAIL
      escalates to ``ProbeFailure``; non-required FAIL keeps
      ``outcome.status == FAIL`` but the observability rails (counter,
      span ``probe.outcome`` attribute, structured-log level) record
      the outcome as ``WARN``.
    * On FAIL/WARN, the last 50 structured events emitted via the
      probe's ``_probe_logger`` are captured into ``ProbeOutcome.log_tail``;
      OK discards the tail.
    * ``total_budget_s`` is a soft pre-flight budget. Checked at the top
      of each probe iteration: if cumulative wall-clock exceeds the
      budget before probe N starts, ``StartupBudgetExceeded`` raises
      and probe N is skipped. Does NOT cap individual probe wall-clock
      -- a probe that starts within budget can run a full
      ``probe.timeout_s`` past it.

    The runner intentionally does NOT call ``configure_otel``,
    ``set_tracer_provider``, or ``set_meter_provider``: those are the
    consumer's responsibility, set up before the runner is invoked. The
    ``outcome_counter`` callback is the consumer's hook for emitting
    ``startup.probe.outcome_total{name, outcome, app_env}`` via their
    own cached OTel counter -- the runner has zero direct OTel-metric
    coupling.
    """

    def __init__(
        self,
        *,
        app_env: str,
        total_budget_s: float = 60.0,
        outcome_counter: OutcomeCounterCallback | None = None,
    ) -> None:
        """Build a runner.

        Parameters
        ----------
        app_env:
            Environment label propagated to ``outcome_counter`` and the
            runner's structured-log emissions.
        total_budget_s:
            Soft pre-flight budget. Checked at the top of each probe
            iteration: if cumulative wall-clock exceeds this value
            before probe N starts, ``StartupBudgetExceeded`` raises and
            probe N is skipped. Does NOT cap individual probe
            wall-clock -- a probe that starts within budget can run a
            full ``probe.timeout_s`` past it. To enforce a hard
            wall-clock cap, set per-probe ``timeout_s`` such that the
            sum bounds your acceptable boot time.
        outcome_counter:
            Optional callback for probe outcome instrumentation. Called
            once per probe with the OBSERVABILITY outcome (post
            non-required FAIL -> WARN downgrade). The runner catches
            any exception the callback raises and logs it via
            ``logger.warning`` rather than aborting the boot.
        """
        self._app_env = app_env
        self._total_budget_s = total_budget_s
        self._outcome_counter = outcome_counter

    async def run(
        self,
        probes: Sequence[StartupProbe],
        *,
        logger: AsyncBoundLogger,
    ) -> tuple[ProbeOutcome, ...]:
        """Run *probes* in order; return outcomes; raise on required FAIL."""
        start_total = monotonic()
        results: list[ProbeOutcome] = []
        tracer = get_tracer()

        for probe in probes:
            if monotonic() - start_total > self._total_budget_s:
                raise StartupBudgetExceeded(name=probe.name, budget_s=self._total_budget_s)

            deque_tail: deque[Mapping[str, Any]] = deque(maxlen=_LOG_TAIL_MAXLEN)
            probe_logger = self._build_probe_logger(logger, probe.name, deque_tail)
            # Stamp the tap-bound logger on the probe so probe.run() can opt
            # into log-tail capture by emitting through it. Probes that ignore
            # the attribute simply don't contribute to log_tail.
            with suppress(AttributeError):
                # Frozen dataclass / __slots__ instances raise; skip silently.
                probe._probe_logger = probe_logger  # type: ignore[attr-defined]

            with tracer.start_as_current_span(f"startup.probe.{probe.name}") as span:
                span.set_attribute("probe.required", probe.required)
                timed_out = False
                error_type: str | None = None
                error_message: str | None = None
                t0 = monotonic()
                try:
                    async with asyncio.timeout(probe.timeout_s):
                        result = await probe.run()
                    status = result.status
                    diag: Mapping[str, Any] = result.diagnostic
                except TimeoutError:
                    status = ProbeStatus.FAIL
                    timed_out = True
                    diag = MappingProxyType({"timeout_s": probe.timeout_s})
                    error_type = "TimeoutError"
                    error_message = "probe exceeded timeout_s"
                except Exception as exc:
                    status = ProbeStatus.FAIL
                    diag = _EMPTY_DIAGNOSTIC
                    error_type = type(exc).__name__
                    error_message = _scrub_error_message(str(exc))
                duration_ms = (monotonic() - t0) * 1000

                # Observability outcome: non-required FAIL is downgraded
                # to WARN for counter / span / log emission. The raw
                # outcome.status stays FAIL so the lifespan caller can
                # distinguish "probe ran, returned FAIL" from
                # "probe ran, returned WARN".
                observability_outcome = (
                    ProbeStatus.WARN
                    if (status is ProbeStatus.FAIL and not probe.required)
                    else status
                )

                span.set_attribute("probe.duration_ms", duration_ms)
                span.set_attribute("probe.outcome", observability_outcome.value)
                span.set_attribute("probe.timed_out", timed_out)

            log_tail = tuple(deque_tail) if status in (ProbeStatus.FAIL, ProbeStatus.WARN) else ()
            outcome = ProbeOutcome(
                name=probe.name,
                required=probe.required,
                status=status,
                duration_ms=duration_ms,
                timed_out=timed_out,
                diagnostic=diag,
                log_tail=log_tail,
                error_type=error_type,
                error_message=error_message,
            )

            await self._emit_event(logger, outcome, observability_outcome)
            if self._outcome_counter is not None:
                try:
                    self._outcome_counter(
                        name=probe.name,
                        outcome=observability_outcome.value,
                        app_env=self._app_env,
                    )
                except Exception as exc:
                    # Counter bug must not abort boot. Log + continue.
                    await logger.warning(
                        "startup.probe.counter_callback_failed",
                        probe=probe.name,
                        error_type=type(exc).__name__,
                        error_message=_scrub_error_message(str(exc)),
                    )
            results.append(outcome)

            if outcome.status is ProbeStatus.FAIL and probe.required:
                raise ProbeFailure(outcome) from None

        return tuple(results)

    @staticmethod
    def _build_probe_logger(
        logger: AsyncBoundLogger,
        probe_name: str,
        deque_tail: deque[Mapping[str, Any]],
    ) -> _ProbeTapLogger:
        """Build a probe-scoped logger that taps emissions to *deque_tail*."""
        return _ProbeTapLogger(base=logger, tap=deque_tail, probe_name=probe_name)

    async def _emit_event(
        self,
        logger: AsyncBoundLogger,
        outcome: ProbeOutcome,
        observability_outcome: ProbeStatus,
    ) -> None:
        """Emit one structured event for *outcome* at the appropriate level.

        Level + event-name suffix follow ``observability_outcome`` (so a
        non-required FAIL surfaces as ``startup.probe.warn`` at WARNING
        level), while ``outcome.status`` rides through unchanged for
        the lifespan caller's inspection.
        """
        event = f"startup.probe.{observability_outcome.value}"
        kwargs: dict[str, Any] = {
            "name": outcome.name,
            "required": outcome.required,
            "duration_ms": outcome.duration_ms,
            # Deep-copy diagnostic + log_tail so structured-log sinks
            # cannot mutate the captured snapshots back through the
            # ProbeOutcome the lifespan caller still holds.
            "diagnostic": copy.deepcopy(dict(outcome.diagnostic)),
            "log_tail": [copy.deepcopy(dict(entry)) for entry in outcome.log_tail],
            "app_env": self._app_env,
        }
        if outcome.error_type is not None:
            kwargs["error_type"] = outcome.error_type
        if outcome.error_message is not None:
            kwargs["error_message"] = outcome.error_message
        if outcome.timed_out:
            kwargs["timed_out"] = True

        if observability_outcome is ProbeStatus.OK:
            await logger.debug(event, **kwargs)
        elif observability_outcome is ProbeStatus.WARN:
            await logger.warning(event, **kwargs)
        else:
            await logger.error(event, **kwargs)
