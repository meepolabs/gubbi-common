"""Redis fail-fast PING ``StartupProbe`` wrapper.

Issues a single PING against a fully-constructed ``redis.asyncio.Redis``
client.  Aborts the lifespan when Redis is unreachable rather than
yielding a half-open service whose first SSE / arq / budget / webhook
call would surface ``ConnectionError`` at request time.

Required: Redis is a hard dependency of every consumer's hot path
(SSE pub/sub, arq job enqueue, gateway rate limiter, Stripe webhook
caching, audit fail-open ladder).  A silent boot against a dead Redis
erases that contract.

The probe lets driver exceptions propagate to the runner, which:

* records ``error_type`` / ``error_message`` on ``ProbeOutcome``,
* scrubs URL credentials of the form ``scheme://user:pass@host`` from
  the message via ``_scrub_error_message`` before it reaches structured
  logs / OTel attrs,
* emits the canonical ``startup.probe.fail`` structured event,
* raises ``ProbeFailure`` for the lifespan caller (since
  ``required=True``).

That contract removes any need for the probe itself to re-shape the
exception into a diagnostic mapping -- the runner already covers the
credential-scrubbing concern centrally.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gubbi_common.bootstrap.probe_runner import ProbeResult, ProbeStatus

if TYPE_CHECKING:
    import redis.asyncio as aioredis  # type: ignore[import-not-found]

__all__ = ["RedisPingProbe"]


@dataclass
class RedisPingProbe:
    """PING the Redis client; FAIL on any exception.

    Attributes:
        client: The ``redis.asyncio.Redis`` instance constructed in the
            lifespan body before probes run.  Sharing the same client
            guarantees the probe exercises the same connection pool that
            downstream callers will use.
    """

    client: aioredis.Redis
    name: str = "redis_ping"
    required: bool = True
    timeout_s: float = 5.0

    async def run(self) -> ProbeResult:
        """PING Redis; let any exception propagate to the runner."""
        await self.client.ping()
        return ProbeResult(ProbeStatus.OK)
