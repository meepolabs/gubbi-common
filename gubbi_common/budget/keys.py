"""Redis key formatters for per-user per-period budget buckets."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import date
    from uuid import UUID


def budget_key(user_id: UUID, period_start: date) -> str:
    """Redis hash key for a user's per-period LLM budget bucket."""
    return f"budget:{user_id}:{period_start}"


def dirty_member(user_id: UUID, period_start: date) -> str:
    """Member format for the budget:dirty SET, paired with budget_key."""
    return f"{user_id}:{period_start}"
