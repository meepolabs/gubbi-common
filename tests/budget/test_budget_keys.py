"""Tests for gubbi_common.budget.keys -- budget_key and dirty_member formatters."""

from __future__ import annotations

from datetime import date
from uuid import UUID

import pytest

from gubbi_common.budget.keys import budget_key, dirty_member

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

_USER_ID = UUID("aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb")
_PERIOD = date(2026, 5, 1)


# ---------------------------------------------------------------------------
# budget_key
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_budget_key_format() -> None:
    """budget_key returns the exact Redis hash key format."""
    # Arrange / Act
    result = budget_key(_USER_ID, _PERIOD)

    # Assert
    assert result == f"budget:{_USER_ID}:{_PERIOD}"
    assert result == "budget:aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb:2026-05-01"


@pytest.mark.unit
def test_budget_key_stable_across_uuid_styles() -> None:
    """UUID constructed from lowercase and uppercase hex produce identical keys."""
    # Arrange
    lower = UUID("aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb")
    upper = UUID("AAAABBBB-CCCC-DDDD-EEEE-FFFFAAAABBBB")

    # Act
    key_lower = budget_key(lower, _PERIOD)
    key_upper = budget_key(upper, _PERIOD)

    # Assert
    assert key_lower == key_upper


# ---------------------------------------------------------------------------
# dirty_member
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_dirty_member_format() -> None:
    """dirty_member returns the exact SET member format."""
    # Arrange / Act
    result = dirty_member(_USER_ID, _PERIOD)

    # Assert
    assert result == f"{_USER_ID}:{_PERIOD}"
    assert result == "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb:2026-05-01"


@pytest.mark.unit
def test_dirty_member_stable_across_period_styles() -> None:
    """date.fromisoformat round-trip produces the same dirty member."""
    # Arrange
    period_a = date(2026, 5, 1)
    period_b = date.fromisoformat("2026-05-01")

    # Act
    member_a = dirty_member(_USER_ID, period_a)
    member_b = dirty_member(_USER_ID, period_b)

    # Assert
    assert member_a == member_b
