"""Request-scoped structlog logger factory.

Promoted to gubbi-common so consumers (gubbi, gubbi-cloud) share one
canonical helper instead of duplicating ~10 lines of binding logic per
request handler module.

Public API::

    bound_logger(request)  -- structlog.stdlib.AsyncBoundLogger pre-bound
                              with correlation_id / user_id / tenant_id
                              from request scope.

Use ``bound_logger(request)`` inside any code path that runs under a
request scope (route handlers, request-scoped services). For code that
runs outside a request scope (lifespan startup, background workers, CLI
scripts), continue to use ``structlog.get_logger(__name__)``.

Precondition: consumers MUST call ``initialize_logger`` (or otherwise
configure structlog with ``wrapper_class=structlog.stdlib.AsyncBoundLogger``)
before using this helper. The cast below assumes that runtime config.
Emit calls (``info`` / ``warning`` / ``error`` / etc.) MUST be awaited;
``bind`` is sync and returns a new ``AsyncBoundLogger``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import structlog

from gubbi_common.telemetry.logging import get_correlation_id

if TYPE_CHECKING:
    from starlette.requests import Request

__all__ = ["bound_logger"]


def bound_logger(request: Request) -> structlog.stdlib.AsyncBoundLogger:
    """Return a structlog AsyncBoundLogger pre-bound with request context.

    Binds:

    - ``correlation_id`` from gubbi-common's ContextVar (set by
      ``CorrelationIDMiddleware``).
    - ``user_id`` from ``request.state.user_id`` if present (set by
      ``AuthMiddleware`` / ``BearerAuthMiddleware`` downstream of the
      correlation middleware). Stringified via ``str(...)`` so callers
      that store a UUID get a stable JSON-serialisable value.
    - ``tenant_id`` from ``request.state.tenant_id`` if present (set by
      ``SubscriptionMiddleware`` in cloud; not set in gubbi self-host
      today). Stringified for the same reason as ``user_id``.

    The contract is intentionally permissive on ``user_id`` /
    ``tenant_id``: log calls in early-pipeline middleware happen before
    those values are bound. Missing values are simply absent from the
    bound dict (NOT included as ``None``).

    Args:
        request: The Starlette/FastAPI ``Request`` for the current scope.

    Returns:
        A ``structlog.stdlib.AsyncBoundLogger`` carrying whatever subset of
        ``correlation_id`` / ``user_id`` / ``tenant_id`` was available.
        Emit calls (``info`` / ``warning`` / ``error`` / etc.) must be
        awaited per ``AsyncBoundLogger`` contract.
    """
    # ``structlog.get_logger`` is typed as ``Any`` in its stubs because
    # the concrete bound-logger class depends on the active config.
    # ``initialize_logger`` configures structlog with
    # ``wrapper_class=AsyncBoundLogger``, so the cast is sound at runtime
    # for any consumer that has called the canonical initializer.
    log = cast("structlog.stdlib.AsyncBoundLogger", structlog.get_logger())
    bindings: dict[str, object] = {}

    cid = get_correlation_id()
    if cid is not None:
        bindings["correlation_id"] = cid

    state = getattr(request, "state", None)
    if state is not None:
        uid = getattr(state, "user_id", None)
        if uid is not None:
            bindings["user_id"] = str(uid)
        tid = getattr(state, "tenant_id", None)
        if tid is not None:
            bindings["tenant_id"] = str(tid)

    return log.bind(**bindings) if bindings else log
