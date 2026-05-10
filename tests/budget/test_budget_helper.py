"""Tests for gubbi_common.budget.helper.BudgetHelper."""

from __future__ import annotations

from datetime import date
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from gubbi_common.budget.helper import BudgetHelper
from gubbi_common.budget.keys import budget_key, dirty_member

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_USER_ID = UUID("12345678-1234-5678-1234-567812345678")
_PERIOD = date(2026, 5, 1)
_KEY = budget_key(_USER_ID, _PERIOD)
_DIRTY = dirty_member(_USER_ID, _PERIOD)


def _make_helper(script_return: int = 1) -> tuple[BudgetHelper, MagicMock, AsyncMock]:
    """Return (helper, redis_mock, script_mock) configured with script_return."""
    redis_mock = MagicMock()
    redis_mock.hincrby = AsyncMock(return_value=0)
    redis_mock.sadd = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=True)

    script_mock = AsyncMock(return_value=script_return)
    helper = BudgetHelper(redis=redis_mock, pre_charge_script=script_mock)
    return helper, redis_mock, script_mock


# ---------------------------------------------------------------------------
# pre_charge
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_pre_charge_returns_true_when_script_returns_one() -> None:
    """Lua returns 1; pre_charge returns True."""
    # Arrange
    helper, _, _ = _make_helper(script_return=1)

    # Act
    result = await helper.pre_charge(user_id=_USER_ID, period_start=_PERIOD, estimated_cents=50)

    # Assert
    assert result is True


@pytest.mark.asyncio
@pytest.mark.unit
async def test_pre_charge_returns_false_when_script_returns_zero() -> None:
    """Lua returns 0; pre_charge returns False."""
    # Arrange
    helper, _, _ = _make_helper(script_return=0)

    # Act
    result = await helper.pre_charge(user_id=_USER_ID, period_start=_PERIOD, estimated_cents=50)

    # Assert
    assert result is False


@pytest.mark.asyncio
@pytest.mark.unit
async def test_pre_charge_passes_correct_keys_and_args() -> None:
    """pre_charge calls the script with the correct keys and args."""
    # Arrange
    estimated = 75
    helper, _, script_mock = _make_helper(script_return=1)

    # Act
    await helper.pre_charge(user_id=_USER_ID, period_start=_PERIOD, estimated_cents=estimated)

    # Assert
    script_mock.assert_awaited_once_with(
        keys=[_KEY, str(_USER_ID), str(_PERIOD)],
        args=[str(estimated)],
    )


# ---------------------------------------------------------------------------
# record_actual_cost -- delta cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_actual_cost_positive_delta() -> None:
    """actual=100, estimated=50 => HINCRBY +50."""
    # Arrange
    helper, redis_mock, _ = _make_helper()

    # Act
    await helper.record_actual_cost(
        user_id=_USER_ID, period_start=_PERIOD, actual_cents=100, estimated_cents=50
    )

    # Assert
    redis_mock.hincrby.assert_awaited_once_with(_KEY, "used_cents", 50)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_actual_cost_negative_delta() -> None:
    """actual=20, estimated=50 => HINCRBY -30."""
    # Arrange
    helper, redis_mock, _ = _make_helper()

    # Act
    await helper.record_actual_cost(
        user_id=_USER_ID, period_start=_PERIOD, actual_cents=20, estimated_cents=50
    )

    # Assert
    redis_mock.hincrby.assert_awaited_once_with(_KEY, "used_cents", -30)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_actual_cost_refund_shape() -> None:
    """actual=0, estimated=50 => HINCRBY -50 (second-savepoint refund)."""
    # Arrange
    helper, redis_mock, _ = _make_helper()

    # Act
    await helper.record_actual_cost(
        user_id=_USER_ID, period_start=_PERIOD, actual_cents=0, estimated_cents=50
    )

    # Assert
    redis_mock.hincrby.assert_awaited_once_with(_KEY, "used_cents", -50)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_actual_cost_zero_delta() -> None:
    """actual=50, estimated=50 => HINCRBY 0; SADD and EXPIRE still called."""
    # Arrange
    helper, redis_mock, _ = _make_helper()

    # Act
    await helper.record_actual_cost(
        user_id=_USER_ID, period_start=_PERIOD, actual_cents=50, estimated_cents=50
    )

    # Assert
    redis_mock.hincrby.assert_awaited_once_with(_KEY, "used_cents", 0)
    redis_mock.sadd.assert_awaited_once()
    redis_mock.expire.assert_awaited_once()


# ---------------------------------------------------------------------------
# record_actual_cost -- side-effect assertions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_actual_cost_sadd_and_expire() -> None:
    """SADD uses the correct dirty member format; EXPIRE uses 3600 seconds."""
    # Arrange
    helper, redis_mock, _ = _make_helper()

    # Act
    await helper.record_actual_cost(
        user_id=_USER_ID, period_start=_PERIOD, actual_cents=100, estimated_cents=50
    )

    # Assert
    redis_mock.sadd.assert_awaited_once_with("budget:dirty", _DIRTY)
    redis_mock.expire.assert_awaited_once_with(_KEY, 3600)


# ---------------------------------------------------------------------------
# record_actual_cost -- error propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_record_actual_cost_redis_error_propagates() -> None:
    """ConnectionError from Redis propagates unchanged; helper does not swallow or wrap."""
    # Arrange
    redis_mock = MagicMock()
    original_error = ConnectionError("redis down")
    redis_mock.hincrby = AsyncMock(side_effect=original_error)
    redis_mock.sadd = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=True)
    script_mock = AsyncMock(return_value=1)
    helper = BudgetHelper(redis=redis_mock, pre_charge_script=script_mock)

    # Act + Assert
    with pytest.raises(ConnectionError) as excinfo:
        await helper.record_actual_cost(
            user_id=_USER_ID, period_start=_PERIOD, actual_cents=50, estimated_cents=50
        )
    assert excinfo.value is original_error  # identity, not just type+message


# ---------------------------------------------------------------------------
# pre_charge -- error propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.unit
async def test_pre_charge_redis_error_propagates() -> None:
    """ConnectionError from the Lua script propagates unchanged; helper does not swallow or wrap."""
    # Arrange
    redis_mock = MagicMock()
    original_error = ConnectionError("redis down")
    script_mock = AsyncMock(side_effect=original_error)
    helper = BudgetHelper(redis=redis_mock, pre_charge_script=script_mock)

    # Act + Assert
    with pytest.raises(ConnectionError) as excinfo:
        await helper.pre_charge(user_id=_USER_ID, period_start=_PERIOD, estimated_cents=50)
    assert excinfo.value is original_error  # identity, not just type+message
