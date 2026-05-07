"""Pytest configuration for telemetry tests."""

from __future__ import annotations

import pytest

from gubbi_common.telemetry import logging as log_mod


@pytest.fixture(autouse=True)
def _reset_correlation_contextvar() -> None:
    """Reset the correlation_id ContextVar before each test.

    Ensures test isolation without requiring manual reset calls.
    """
    log_mod._correlation_id_var.set(None)
