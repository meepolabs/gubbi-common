"""BudgetHelper: thin Redis facade for LLM budget pre-charge and reconciliation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from gubbi_common.budget.keys import budget_key, dirty_member

if TYPE_CHECKING:
    from datetime import date
    from uuid import UUID


class _RedisScript(Protocol):
    async def __call__(self, *, keys: list[str], args: list[str]) -> int: ...


class _RedisClient(Protocol):
    async def hincrby(self, name: str, key: str, amount: int) -> int: ...

    async def sadd(self, name: str, *values: str) -> int: ...

    async def expire(self, name: str, time: int) -> bool: ...

    def register_script(self, script: str) -> _RedisScript: ...


class BudgetHelper:
    """Thin facade over Redis for LLM budget pre-charge and cost reconciliation.

    Pre-charge uses an atomic Lua script to debit estimated_cents from the
    user's period bucket before the upstream call is made.  After the call
    completes, record_actual_cost applies the delta (actual - estimated) to
    converge the running total toward the true spend.  A negative delta
    represents a refund (e.g. when actual=0 on a failed extraction).

    Redis exceptions propagate to the caller -- no swallowing.
    """

    def __init__(
        self,
        *,
        redis: _RedisClient,
        pre_charge_script: _RedisScript,
    ) -> None:
        self._redis = redis
        self._script = pre_charge_script

    async def pre_charge(
        self,
        *,
        user_id: UUID,
        period_start: date,
        estimated_cents: int,
    ) -> bool:
        """Atomically debit estimated_cents from the user's budget bucket.

        Returns True if the debit succeeded (budget not exceeded),
        False if the Lua script returned 0 (budget exceeded or key missing).
        """
        key = budget_key(user_id, period_start)
        result = await self._script(
            keys=[key, str(user_id), str(period_start)],
            args=[str(estimated_cents)],
        )
        return bool(result == 1)

    async def record_actual_cost(
        self,
        *,
        user_id: UUID,
        period_start: date,
        actual_cents: int,
        estimated_cents: int,
    ) -> None:
        """Reconcile actual cost against the pre-charged estimate.

        Computes delta = actual_cents - estimated_cents and applies it via
        HINCRBY.  A negative delta is valid and represents a refund (e.g.
        actual=0 when the upstream call failed after pre-charge).

        Side effects (always, including delta=0):
          - HINCRBY budget:{user}:{period} used_cents <delta>
          - SADD budget:dirty {user}:{period}
          - EXPIRE budget:{user}:{period} 3600
        """
        delta = actual_cents - estimated_cents
        key = budget_key(user_id, period_start)
        await self._redis.hincrby(key, "used_cents", delta)
        await self._redis.sadd("budget:dirty", dirty_member(user_id, period_start))
        await self._redis.expire(key, 3600)


__all__: list[str] = ["BudgetHelper"]
