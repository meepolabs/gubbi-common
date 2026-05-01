"""Sanity check that the package imports and exposes its version."""

import gubbi_common


def test_version_exposed() -> None:
    assert gubbi_common.__version__ == "0.3.0"
