"""Pytest configuration for telemetry tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from gubbi_common.telemetry import logging as log_mod


@pytest.fixture(autouse=True)
def _reset_correlation_contextvar() -> Iterator[None]:
    """Reset the correlation_id ContextVar before AND after each test.

    Ensures test isolation without requiring manual reset calls. The
    post-test reset matters because tests that call ``set_correlation_id``
    must not leak ContextVar state into sibling tests, even if they
    forget the explicit cleanup.
    """
    log_mod._correlation_id_var.set(None)
    yield
    log_mod._correlation_id_var.set(None)
