"""Tests for gubbi_common.telemetry.otel."""

from __future__ import annotations

import os
import subprocess
import sys


def _run_in_subprocess(code: str) -> subprocess.CompletedProcess[str]:
    """Run *code* in a fresh Python process and return its result."""
    env = {**os.environ, "PYTHONNOUSERSITE": "1"}
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


# - Helper scripts executed in isolated processes ---------------------------

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

# S8 M-1: in-process default for service.version + deployment.environment.
# OTEL_RESOURCE_ATTRIBUTES is unset in this script so the kwargs win.
_VERSION_ENV_DEFAULT_SCRIPT = """\
import os
os.environ.pop("OTEL_RESOURCE_ATTRIBUTES", None)
from gubbi_common.telemetry.otel import configure_otel
configure_otel(
    "ver-svc",
    "http://localhost:4317",
    enabled=False,
    service_version="1.2.3",
    deployment_environment="staging",
)
import gubbi_common.telemetry.otel as m
attrs = dict(m._RESOURCE.attributes)
print(attrs.get("service.name"))
print(attrs.get("service.version"))
print(attrs.get("deployment.environment"))
"""

# S8 M-1: env override overlays the kwargs (per OTel spec). The env value
# for ``deployment.environment`` must win even when the kwarg sets a
# different value.
_VERSION_ENV_OVERRIDE_SCRIPT = """\
import os
os.environ["OTEL_RESOURCE_ATTRIBUTES"] = (
    "deployment.environment=production,custom.attr=xyz"
)
from gubbi_common.telemetry.otel import configure_otel
configure_otel(
    "override-svc",
    "http://localhost:4317",
    enabled=False,
    service_version="9.9.9",
    deployment_environment="staging",  # kwarg says staging
)
import gubbi_common.telemetry.otel as m
attrs = dict(m._RESOURCE.attributes)
print(attrs.get("service.name"))
print(attrs.get("service.version"))
# Env value MUST win:
print(attrs.get("deployment.environment"))
print(attrs.get("custom.attr"))
"""

# S8 M-1: omitting both new kwargs leaves the resource without those keys
# unless OTEL_RESOURCE_ATTRIBUTES sets them. Pre-B3 callers stay
# observationally identical.
_NO_VERSION_KWARGS_SCRIPT = """\
import os
os.environ.pop("OTEL_RESOURCE_ATTRIBUTES", None)
from gubbi_common.telemetry.otel import configure_otel
configure_otel("legacy-svc", "http://localhost:4317", enabled=False)
import gubbi_common.telemetry.otel as m
attrs = dict(m._RESOURCE.attributes)
print(attrs.get("service.name"))
print("MISSING" if attrs.get("service.version") is None else attrs.get("service.version"))
print(
    "MISSING"
    if attrs.get("deployment.environment") is None
    else attrs.get("deployment.environment")
)
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


class TestServiceVersionAndDeploymentEnv:
    """S8 M-1 (B3): service.version + deployment.environment resource attrs."""

    def test_kwargs_populate_resource_attributes(self) -> None:
        """Caller-supplied kwargs land on the Resource as default attrs.

        Without an OTEL_RESOURCE_ATTRIBUTES override, the in-process
        defaults from configure_otel kwargs win.
        """
        result = _run_in_subprocess(_VERSION_ENV_DEFAULT_SCRIPT)
        assert (
            result.returncode == 0
        ), f"child failed\nstdout={result.stdout}\nstderr={result.stderr}"
        lines = [line.strip() for line in result.stdout.strip().splitlines()]
        assert len(lines) >= 3
        assert lines[0] == "ver-svc"
        assert lines[1] == "1.2.3"
        assert lines[2] == "staging"

    def test_env_override_wins_over_kwarg(self) -> None:
        """OTEL_RESOURCE_ATTRIBUTES overlays the kwarg defaults (OTel spec).

        deployment.environment kwarg=staging but env=production -> env wins.
        Custom attrs from env are preserved alongside.
        """
        result = _run_in_subprocess(_VERSION_ENV_OVERRIDE_SCRIPT)
        assert (
            result.returncode == 0
        ), f"child failed\nstdout={result.stdout}\nstderr={result.stderr}"
        lines = [line.strip() for line in result.stdout.strip().splitlines()]
        assert len(lines) >= 4
        assert lines[0] == "override-svc"
        assert lines[1] == "9.9.9"  # service.version kwarg (no env override for this key)
        assert lines[2] == "production"  # env wins over the staging kwarg
        assert lines[3] == "xyz"  # custom env attr preserved

    def test_omitting_kwargs_leaves_attrs_unset(self) -> None:
        """Pre-B3 call sites (no kwargs, no OTEL_RESOURCE_ATTRIBUTES) get
        only ``service.name`` -- backward-compatible default."""
        result = _run_in_subprocess(_NO_VERSION_KWARGS_SCRIPT)
        assert (
            result.returncode == 0
        ), f"child failed\nstdout={result.stdout}\nstderr={result.stderr}"
        lines = [line.strip() for line in result.stdout.strip().splitlines()]
        assert len(lines) >= 3
        assert lines[0] == "legacy-svc"
        assert lines[1] == "MISSING"
        assert lines[2] == "MISSING"
