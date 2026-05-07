"""OpenTelemetry configuration for gubbi-common.

Wire OTel at startup via ``configure_otel()``.  This module intentionally
stays decoupled from FastAPI, asyncpg, redis, and httpx -- per architecture
decision those auto-instrumentors live in consumer repos (e.g. gubbi-cloud).
"""

from __future__ import annotations

import os

from opentelemetry import trace as _otel_trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.metrics import set_meter_provider as _set_mp
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_RESOURCE: Resource | None = None
_TRACER: _otel_trace.Tracer | None = None


def configure_otel(
    service_name: str,
    endpoint: str,
    *,
    enabled: bool = True,
) -> None:
    """Configure the OTel SDK without cloud-specific auto-instrumentors.

    * ``disabled`` -- when ``enabled=False``, installs no-op providers so all
      instrumentation is wired but **zero** data leaves the process.
    * Otherwise configures an ``OTLPSpanExporter`` +
      ``OTLPMetricExporter`` pointed at *endpoint* (the local otel-collector
      gRPC port).
    """
    resource_attributes = {
        "service.name": service_name,
    }

    # OTEL_RESOURCE_ATTRIBUTES : key1=val1,key2=val2, ...
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

    if enabled:
        span_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(span_exporter))
    # When disabled: install no span processor. The provider becomes a sink
    # with no exporter, so spans are created and dropped with zero IO.

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
