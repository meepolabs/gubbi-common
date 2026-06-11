"""Tests for the canonical journal scope vocabulary.

Locks the scope string values exactly: the cloud-api gateway and gubbi
both resolve to these literals, so an accidental rename here would let
the two sides fork on the scope vocabulary.
"""

from __future__ import annotations

import pytest

from gubbi_common.auth.scopes import COOKIE_MODE_SCOPES, SCOPE_READ, SCOPE_WRITE


@pytest.mark.unit
def test_scope_values_are_pinned() -> None:
    # Arrange / Act / Assert
    assert SCOPE_READ == "journal:read"
    assert SCOPE_WRITE == "journal:write"
    assert COOKIE_MODE_SCOPES == "journal:read journal:write"


@pytest.mark.unit
def test_cookie_mode_scopes_combines_read_and_write() -> None:
    # Arrange / Act
    parts = COOKIE_MODE_SCOPES.split(" ")

    # Assert
    assert parts == [SCOPE_READ, SCOPE_WRITE]


@pytest.mark.unit
def test_scopes_reexported_from_auth_package() -> None:
    # Guards the top-level auth re-export against silent divergence.
    from gubbi_common.auth import SCOPE_READ as PKG_READ
    from gubbi_common.auth import SCOPE_WRITE as PKG_WRITE

    assert PKG_READ == "journal:read"
    assert PKG_WRITE == "journal:write"
