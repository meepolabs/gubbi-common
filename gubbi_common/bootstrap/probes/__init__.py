"""Shared StartupProbe wrappers reused across consumers.

Each probe in this sub-module is a constructor-injected dataclass meeting
the :class:`gubbi_common.bootstrap.StartupProbe` Protocol.  Both gubbi
(HTTP server + extraction worker) and gubbi-cloud (api gateway) compose
these in their lifespan probe sequences; promoting them here removes the
two duplicate wrapper pairs the consumers used to ship.

Probes accept their dependencies via the constructor and MUST NOT read
``app.state`` from inside ``run()``.  The lifespan body extracts the
relevant value and passes it in at probe-construction time.
"""

from gubbi_common.bootstrap.probes.pg_log import PgLogProbe
from gubbi_common.bootstrap.probes.redis_ping import RedisPingProbe

__all__ = [
    "PgLogProbe",
    "RedisPingProbe",
]
