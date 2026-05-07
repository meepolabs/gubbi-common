"""Tests for gubbi_common.telemetry.otel."""

from __future__ import annotations

import os
import subprocess
import sys


def _run_in_subprocess(code: str) -> subprocess.CompletedProcess[str]:
    """Run *code* in a fresh Python process and return its result."""
    env = {**os.environ, "PYTHONNOUSERSITE": "1"}
    return subprocess.run(  # noqa: S603 (hardcoded code strings, not user input)
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


# ── Helper scripts executed in isolated processes ───────────────────────────

_ENABLED_SCRIPT = """\
from gubbi_common.telemetry.otel import configure_otel
configure_otel("proc-svc", "http://localhost:4317", enabled=True)
import gubbi_common.telemetry.otel as m
tp = __import__("opentelemetry.trace").trace.get_tracer_provider()
msp = tp._active_span_processor
span_procs = list(msp._span_processors)
print(len(span_procs))
"""

_DISABLED_SCRIPT = """\
from gubbi_common.telemetry.otel import configure_otel
configure_otel("proc-svc", "http://localhost:4317", enabled=False)
import gubbi_common.telemetry.otel as m
tp = __import__("opentelemetry.trace").trace.get_tracer_provider()
msp = tp._active_span_processor
span_procs = list(msp._span_processors)
print(len(span_procs))
"""

_ATTRS_SCRIPT = """\
import os
os.environ["OTEL_RESOURCE_ATTRIBUTES"] = "env=prod,team=foo"
from gubbi_common.telemetry.otel import configure_otel
configure_otel("attr-svc", "http://localhost:4317", enabled=False)
import gubbi_common.telemetry.otel as m
attrs = dict(m._RESOURCE.attributes)
print(attrs.get("service.name"))
print(attrs.get("env"))
print(attrs.get("team"))
"""

_TRACER_SCRIPT = """\
from gubbi_common.telemetry.otel import configure_otel, get_tracer
configure_otel("tracer-svc", "http://localhost:4317", enabled=False)
import gubbi_common.telemetry.otel as m
configured = m._TRACER
returned = get_tracer()
print(configured is returned)
print(returned is not None)
"""


class TestConfigureOtelEnabled:
    def test_installs_otlp_exporter(self) -> None:
        """After configure_otel(..., enabled=True), the global tracer provider
        has at least one BatchSpanProcessor."""
        result = _run_in_subprocess(_ENABLED_SCRIPT)
        assert (
            result.returncode == 0
        ), f"child failed\nstdout={result.stdout}\nstderr={result.stderr}"
        count = int(result.stdout.strip())
        assert count >= 1


class TestConfigureOtelDisabled:
    def test_installs_noop_provider(self) -> None:
        """After configure_otel(..., enabled=False), the global tracer provider
        has no span processors (zero IO sink)."""
        result = _run_in_subprocess(_DISABLED_SCRIPT)
        assert (
            result.returncode == 0
        ), f"child failed\nstdout={result.stdout}\nstderr={result.stderr}"
        count = int(result.stdout.strip())
        assert count == 0


class TestOtelResourceAttributesEnvParsed:
    def test_parses_otel_resource_attributes(self) -> None:
        """When OTEL_RESOURCE_ATTRIBUTES='env=prod,team=foo' is set, the
        Resource attributes include those keys plus service.name."""
        result = _run_in_subprocess(_ATTRS_SCRIPT)
        assert (
            result.returncode == 0
        ), f"child failed\nstdout={result.stdout}\nstderr={result.stderr}"
        lines = [line.strip() for line in result.stdout.strip().splitlines()]
        assert len(lines) >= 3
        assert lines[0] == "attr-svc"  # service.name
        assert lines[1] == "prod"  # env
        assert lines[2] == "foo"  # team


class TestGetTracer:
    def test_returns_configured_tracer(self) -> None:
        """After configure_otel(...), get_tracer() returns the tracer that was
        installed by configure_otel."""
        result = _run_in_subprocess(_TRACER_SCRIPT)
        assert (
            result.returncode == 0
        ), f"child failed\nstdout={result.stdout}\nstderr={result.stderr}"
        lines = [line.strip() for line in result.stdout.strip().splitlines()]
        assert lines[0] == "True"  # configured is returned
        assert lines[1] == "True"  # not None
