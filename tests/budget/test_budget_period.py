"""Tests for gubbi_common.budget.period.current_period_start."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from gubbi_common.budget.period import current_period_start

# ---------------------------------------------------------------------------
# current_period_start
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_current_period_start_returns_first_of_month_utc() -> None:
    """Monkeypatched datetime.now returns a known mid-month instant;
    current_period_start returns the first of that UTC month."""
    # Arrange
    fake_now = datetime(2026, 5, 17, 14, 30, 0, tzinfo=UTC)

    with patch("gubbi_common.budget.period.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        # .replace() is called on the returned datetime -- delegate to the real method

        # Act
        result = current_period_start()

    # Assert
    assert result.year == 2026
    assert result.month == 5
    assert result.day == 1


@pytest.mark.unit
def test_current_period_start_jan_1_after_pst_dec_31_evening() -> None:
    """2026-12-31 23:59 PST (UTC-8) is 2027-01-01 07:59 UTC.
    current_period_start, which is UTC-anchored (D10), returns 2027-01-01
    (first of the UTC month), not 2026-12-01."""
    # Arrange
    # 2027-01-01 07:59:00 UTC -- PST traveler's 'Dec 31 night' is actually Jan 1 UTC.
    fake_now = datetime(2027, 1, 1, 7, 59, 0, tzinfo=UTC)

    with patch("gubbi_common.budget.period.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now

        # Act
        result = current_period_start()

    # Assert
    assert result.year == 2027
    assert result.month == 1
    assert result.day == 1
