"""OpenTelemetry configuration for gubbi-common.

Wire OTel at startup via ``configure_otel()``.  This module intentionally
stays decoupled from FastAPI, asyncpg, redis, and httpx -- per architecture
decision those auto-instrumentors live in consumer repos (e.g. gubbi-cloud).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Sequence

from opentelemetry import trace as _otel_trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.metrics import set_meter_provider as _set_mp
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

__all__ = [
    "configure_otel",
    "get_tracer",
    "safe_instrument",
]

logger = logging.getLogger(__name__)

_RESOURCE: Resource | None = None
_TRACER: _otel_trace.Tracer | None = None


def configure_otel(
    service_name: str,
    endpoint: str,
    *,
    enabled: bool = True,
    service_version: str | None = None,
    deployment_environment: str | None = None,
    extra_processors: Sequence[SpanProcessor] = (),
) -> None:
    """Configure the OTel SDK without cloud-specific auto-instrumentors.

    * ``disabled`` -- when ``enabled=False``, installs SDK providers
      with no exporter span processor and no metric readers (sink /
      no-export configuration). The default ``BatchSpanProcessor`` is
      not installed so spans are created and dropped with zero IO.
      ``extra_processors`` (see below) are STILL installed in this
      mode -- they may carry non-export side effects (e.g. a
      ``CorrelationSpanProcessor`` injecting ContextVar values) that
      callers depend on regardless of export configuration.
    * Otherwise configures an ``OTLPSpanExporter`` +
      ``OTLPMetricExporter`` pointed at *endpoint* (the local otel-collector
      gRPC port).

    Resource attributes (S8 M-1):

    * ``service.name`` -- always set from the *service_name* arg.
    * ``service.version`` -- set when *service_version* is provided.
      Callers pass ``__version__`` from their package (gubbi/gubbi-cloud).
    * ``deployment.environment`` -- set when *deployment_environment* is
      provided. Callers pass ``settings.app_env`` (dev/ci/staging/production).

    ``OTEL_RESOURCE_ATTRIBUTES`` env var entries OVERLAY the defaults
    (per OTel spec). A deploy-time override of e.g.
    ``deployment.environment=staging`` always wins over the in-process
    default. Without the in-process defaults, HyperDX traces carry no
    ``service.version`` or ``deployment.environment`` tag because neither
    Dockerfile nor Kamal config sets ``OTEL_RESOURCE_ATTRIBUTES`` today.

    ``extra_processors`` -- additional :class:`SpanProcessor` instances
    registered alongside the default ``BatchSpanProcessor``. Threaded
    through the constructor (vs. a post-hoc ``add_span_processor``) so
    the provider's wiring is atomic and ordered: no startup gap where
    spans emit untagged because a hook had not been registered yet.
    Pass e.g. :class:`gubbi_common.telemetry.correlation_processor.CorrelationSpanProcessor`
    to auto-inject ``correlation_id`` on every span. Registered BEFORE
    the exporter so the attribute lands before export, regardless of
    whether the exporter processor runs at ``on_start`` or ``on_end``.
    """
    resource_attributes: dict[str, str] = {
        "service.name": service_name,
    }
    if service_version is not None:
        resource_attributes["service.version"] = service_version
    if deployment_environment is not None:
        resource_attributes["deployment.environment"] = deployment_environment

    # OTEL_RESOURCE_ATTRIBUTES : key1=val1,key2=val2, ...
    # Env values OVERLAY the in-process defaults: a deploy that sets
    # ``deployment.environment=staging`` in OTEL_RESOURCE_ATTRIBUTES wins
    # over whatever the caller passed via the kwarg.
    raw = os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "")
    for kv in raw.split(","):
        kv = kv.strip()
        if "=" in kv:
            k, v = kv.split("=", 1)
            resource_attributes[k.strip()] = v.strip()

    global _RESOURCE
    _RESOURCE = Resource.create(resource_attributes)

    provider = TracerProvider(resource=_RESOURCE)
    tracer = provider.get_tracer(__name__)
    global _TRACER
    _TRACER = tracer

    # Register extra processors BEFORE the exporter so on_start hooks
    # (e.g. CorrelationSpanProcessor injecting correlation_id) land
    # before BatchSpanProcessor's on_end queues the span for export.
    for processor in extra_processors:
        provider.add_span_processor(processor)

    if enabled:
        span_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(span_exporter))
    # When disabled: install no exporter. The provider becomes a sink
    # with no exporter, so spans are created and dropped with zero IO.
    # ``extra_processors`` (above) still run even when ``enabled=False``
    # -- they may have non-export side effects (e.g. ContextVar reads)
    # that callers depend on regardless of export configuration.

    _otel_trace.set_tracer_provider(provider)

    if enabled:
        metric_exporter = OTLPMetricExporter(endpoint=endpoint, insecure=True)
        reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=5000)
        mp = MeterProvider(resource=_RESOURCE, metric_readers=[reader])
        _set_mp(mp)
    else:
        # No metric reader -> no exporter -> metrics are no-ops with no IO.
        mp = MeterProvider(resource=_RESOURCE, metric_readers=[])
        _set_mp(mp)


def get_tracer() -> _otel_trace.Tracer:
    """Return the global tracer (set during ``configure_otel``)."""
    if _TRACER is not None:
        return _TRACER
    return _otel_trace.get_tracer(__name__)


def safe_instrument(name: str, factory: Callable[[], None]) -> None:
    """Wire an auto-instrumentor inside a try/except + structured log.

    Per-instrumentor failures must not cascade to startup: a broken
    third-party instrumentor (driver missing, signature drift) should
    degrade observability for that one library, not crash the service.
    The helper logs a DEBUG line on the happy path so operators can
    confirm wiring at startup, and a WARNING on failure naming the
    instrumentor so the gap is operator-visible without breaking the
    boot path.

    Parameters
    ----------
    name:
        Display name for the instrumentor (e.g. ``"FastAPI"``,
        ``"HTTPX"``). Surfaced in both the success debug and the
        failure warning.
    factory:
        Zero-arg callable that performs the instrumentation. Typically
        a lambda over ``ThingInstrumentor().instrument()``.
    """
    try:
        factory()
        logger.debug("%s auto-instrumentation wired", name)
    except Exception as exc:  # noqa: BLE001 -- defensive boundary, intent is broad swallow
        logger.warning("%s instrumentor failed: %s", name, exc)
