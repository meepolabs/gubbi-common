"""Unit tests for ``gubbi_common.telemetry.bound_logger``.

Verifies the contract documented in the helper's docstring:

- correlation_id pulled from gubbi-common's ContextVar (None -> not bound)
- user_id / tenant_id pulled from ``request.state`` when present
- None / missing values are NOT bound as ``None`` (key absent from dict)
- UUID values are stringified

Uses ``structlog.testing.capture_logs`` to assert the bound dict that
reaches the renderer; this is structlog's recommended testing seam and
is independent of any handler/formatter wired up elsewhere.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
import structlog

from gubbi_common.telemetry.bound_logger import bound_logger
from gubbi_common.telemetry.logging import set_correlation_id


def _fake_request(**state_kwargs: Any) -> Any:
    """Build a stub object that quacks like a Starlette ``Request`` for
    the helper's purposes (only ``request.state`` is read)."""
    return SimpleNamespace(state=SimpleNamespace(**state_kwargs))


@pytest.mark.unit
def test_returns_unbound_when_no_context() -> None:
    """No correlation_id, no request.state attrs -> no bindings emitted."""
    request = _fake_request()
    log = bound_logger(request)

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    assert len(captured) == 1
    entry = captured[0]
    assert entry["event"] == "event.test"
    assert "correlation_id" not in entry
    assert "user_id" not in entry
    assert "tenant_id" not in entry


@pytest.mark.unit
def test_binds_correlation_id_when_set() -> None:
    """ContextVar set -> bound logger emits correlation_id."""
    set_correlation_id("cid-abc-123")
    request = _fake_request()
    log = bound_logger(request)

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    assert captured[0]["correlation_id"] == "cid-abc-123"


@pytest.mark.unit
def test_binds_user_id_from_request_state() -> None:
    """request.state.user_id present -> bound as string."""
    request = _fake_request(user_id="user-42")
    log = bound_logger(request)

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    assert captured[0]["user_id"] == "user-42"


@pytest.mark.unit
def test_binds_tenant_id_from_request_state() -> None:
    """request.state.tenant_id present -> bound as string."""
    request = _fake_request(tenant_id="tenant-xyz")
    log = bound_logger(request)

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    assert captured[0]["tenant_id"] == "tenant-xyz"


@pytest.mark.unit
def test_omits_none_values() -> None:
    """state.user_id = None / state.tenant_id = None -> keys absent (NOT
    bound as None). Documented contract: missing values are simply not
    in the bound dict so early-pipeline log calls before auth / sub
    middleware run cleanly."""
    request = _fake_request(user_id=None, tenant_id=None)
    log = bound_logger(request)

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    entry = captured[0]
    assert "user_id" not in entry
    assert "tenant_id" not in entry


@pytest.mark.unit
def test_user_id_uuid_stringified() -> None:
    """UUID user_id stringified to its canonical form for stable JSON."""
    user_uuid = UUID("12345678-1234-5678-1234-567812345678")
    request = _fake_request(user_id=user_uuid)
    log = bound_logger(request)

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    assert captured[0]["user_id"] == "12345678-1234-5678-1234-567812345678"


@pytest.mark.unit
def test_tenant_id_uuid_stringified() -> None:
    """UUID tenant_id also stringified (parity with user_id)."""
    tenant_uuid = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    request = _fake_request(tenant_id=tenant_uuid)
    log = bound_logger(request)

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    assert captured[0]["tenant_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.mark.unit
def test_binds_all_three_when_all_present() -> None:
    """correlation_id + user_id + tenant_id all present -> all three bound."""
    set_correlation_id("cid-full")
    request = _fake_request(user_id="user-7", tenant_id="tenant-9")
    log = bound_logger(request)

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    entry = captured[0]
    assert entry["correlation_id"] == "cid-full"
    assert entry["user_id"] == "user-7"
    assert entry["tenant_id"] == "tenant-9"


@pytest.mark.unit
def test_request_without_state_attribute_does_not_crash() -> None:
    """Pathological case: a request stub with no ``state`` attribute at
    all. The helper uses ``getattr(request, 'state', None)`` and must
    not raise."""
    request = SimpleNamespace()  # no .state
    log = bound_logger(request)  # type: ignore[arg-type]

    with structlog.testing.capture_logs() as captured:
        log.info("event.test")

    entry = captured[0]
    assert "user_id" not in entry
    assert "tenant_id" not in entry
