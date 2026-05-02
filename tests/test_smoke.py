"""Sanity check that the package imports and exposes its version."""

import pytest

import gubbi_common


@pytest.mark.unit
def test_version_exposed() -> None:
    """Package exposes a non-empty string version."""
    assert isinstance(gubbi_common.__version__, str)
    assert gubbi_common.__version__
