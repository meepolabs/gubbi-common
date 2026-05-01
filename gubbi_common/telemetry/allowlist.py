"""Per-span attribute allowlist enforcement (DEC-070).

Hard rule: NO journal content -- and NO raw PII -- in spans, metrics, or
structured logs. This module is the **primary defense**: banned keys are
dropped at the span-builder layer before they ever reach the
exporter / batcher / sampler. Collector-side redact rules are
defense-in-depth, not the contract.

``safe_set_attributes(span_name, span, attrs)`` silently drops any key
that:

1. Matches an entry in :data:`BANNED_KEYS` exactly, or contains any
   :data:`BANNED_KEYS` entry as a substring (so ``content_hash``,
   ``email_hash``, ``client_user_agent_hash`` are all rejected even
   when not enumerated). Substring matching is the conservative
   interpretation -- if the privacy promise is wrong, take the
   stricter side.
2. Is not in the allowlist for the given ``span_name``. Unknown span
   names get an empty allowlist (every key is dropped) and a warning.

The :data:`SPAN_ALLOWLIST` table is the single union of every span
defined across consuming repos. To add a new span name, add an entry
here and bump this package's version.
"""

from __future__ import annotations

import logging
from typing import Any, Final

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Banned attribute keys
# ---------------------------------------------------------------------------
# Union of the deny-lists carried by journalctl and journalctl-cloud as of
# the migration into gubbi-common. Substring matching is applied: any
# attribute key containing one of these tokens is dropped.
BANNED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "body",
        "content",
        "email",
        "ip_address",
        "messages",
        "password",
        "query",
        "reasoning",
        "search_query",
        "summary",
        "user_agent",
    }
)


# ---------------------------------------------------------------------------
# Per-span attribute allowlists
# ---------------------------------------------------------------------------
# Every span name surfaced by either repo gets an entry. Keys are the
# union of what each repo allowed for that span; if the two repos'
# allowlists differ for the same span, this module ships the stricter
# (smaller) intersection only -- but at the time of extraction the only
# overlapping span name is ``audit.write`` and the two allowlists agree.
#
# Correlation ID is allowlisted for every span so transport middleware
# can stamp it everywhere without a per-span exception.
_CORRELATION: Final[frozenset[str]] = frozenset({"correlation_id"})


# journalctl spans (from journalctl/journalctl/telemetry/attrs.py).
_MCP_TOOL_CALL: Final[frozenset[str]] = frozenset(
    {
        "tool.name",
        "user_id",
        "tool.scope_required",
        "result",
        "result.size_chars",
        "latency_ms",
    }
)

_MCP_TOOL_RESPONSE_SIZE_CHECK: Final[frozenset[str]] = frozenset(
    {
        "tool.name",
        "size_chars",
        "error_threshold_hit",
    }
)

_DB_QUERY_USER_SCOPED: Final[frozenset[str]] = frozenset(
    {
        "query_kind",
        "user_id",
        "row_count",
        "latency_ms",
    }
)

_EMBEDDING_ENCODE: Final[frozenset[str]] = frozenset(
    {
        "text_hash",
        "text_len",
        "latency_ms",
    }
)

_CIPHER_OP: Final[frozenset[str]] = frozenset(
    {
        "version",
        "field_kind",
        "bytes_processed",
        "latency_ms",
    }
)

_AUDIT_WRITE: Final[frozenset[str]] = frozenset(
    {
        "event_type",
        "target_id",
        "actor_type",
        "success",
        "latency_ms",
    }
)


# journalctl-cloud spans (from
# journalctl-cloud/journalctl_cloud/telemetry/attrs.py).
_AUTH_BEARER_INTROSPECT: Final[frozenset[str]] = frozenset(
    {
        "cache.hit",
        "token_fp",
        "hydra.status_code",
        "result",
        "latency_ms",
    }
)

_AUTH_SESSION_RESOLVE: Final[frozenset[str]] = frozenset(
    {
        "cache.hit",
        "cookie_fp",
        "kratos.status_code",
        "result",
        "latency_ms",
    }
)

_AUTH_SUBSCRIPTION_CHECK: Final[frozenset[str]] = frozenset(
    {
        "user_id",
        "tier",
        "cache.hit",
        "result",
        "latency_ms",
    }
)

_AUTH_RATELIMIT_CHECK: Final[frozenset[str]] = frozenset(
    {
        "user_id",
        "bucket",
        "tokens_remaining",
        "result",
    }
)

_AUTH_JIT_PROVISION: Final[frozenset[str]] = frozenset(
    {
        "user_id",
        "kratos_identity_id",
        "was_inserted",
        "latency_ms",
    }
)

_GATEWAY_FORWARD: Final[frozenset[str]] = frozenset(
    {
        "target_url",
        "user_id",
        "method",
        "path",
        "chunks_streamed",
        "total_bytes",
        "upstream_status",
        "latency_ms_first_byte",
        "latency_ms_total",
    }
)

_WEBHOOK_KRATOS: Final[frozenset[str]] = frozenset(
    {
        "event_type",
        "kratos_identity_id",
        "idempotent_skip",
        "latency_ms",
    }
)

# Cloud's well-known PRM span allowlists ``client_user_agent_hash``,
# which is dropped under substring matching. Kept here as an empty set
# so the span name is recognised; emitting that key now logs a debug
# line and drops the value. Privacy improvement, not a regression.
_WELL_KNOWN_PRM: Final[frozenset[str]] = frozenset()


SPAN_ALLOWLIST: dict[str, frozenset[str]] = {
    # journalctl spans
    "mcp.tool_call": _MCP_TOOL_CALL | _CORRELATION,
    "mcp.tool_response_size_check": _MCP_TOOL_RESPONSE_SIZE_CHECK | _CORRELATION,
    "db.query.user_scoped": _DB_QUERY_USER_SCOPED | _CORRELATION,
    "embedding.encode": _EMBEDDING_ENCODE | _CORRELATION,
    "cipher.encrypt": _CIPHER_OP | _CORRELATION,
    "cipher.decrypt": _CIPHER_OP | _CORRELATION,
    "http.request": _CORRELATION,
    # cloud-api spans
    "auth.bearer_introspect": _AUTH_BEARER_INTROSPECT | _CORRELATION,
    "auth.session_resolve": _AUTH_SESSION_RESOLVE | _CORRELATION,
    "auth.subscription_check": _AUTH_SUBSCRIPTION_CHECK | _CORRELATION,
    "auth.ratelimit_check": _AUTH_RATELIMIT_CHECK | _CORRELATION,
    "auth.jit_provision": _AUTH_JIT_PROVISION | _CORRELATION,
    "gateway.forward": _GATEWAY_FORWARD | _CORRELATION,
    "webhook.kratos_identity_created": _WEBHOOK_KRATOS | _CORRELATION,
    "webhook.kratos_identity_updated": _WEBHOOK_KRATOS | _CORRELATION,
    "webhook.kratos_identity_deleted": _WEBHOOK_KRATOS | _CORRELATION,
    "well_known.protected_resource_metadata": _WELL_KNOWN_PRM | _CORRELATION,
    # shared
    "audit.write": _AUDIT_WRITE | _CORRELATION,
}


def _get_allowlisted_attrs(span_name: str) -> frozenset[str]:
    """Return the allowlisted attribute set for *span_name*, or an empty set."""
    return SPAN_ALLOWLIST.get(span_name, frozenset())


def safe_set_attributes(
    span_name: str,
    span: Any,
    attrs: dict[str, Any],
) -> None:
    """Set attributes on *span*, dropping any banned or non-allowlisted key.

    Banned keys (exact match or substring match against
    :data:`BANNED_KEYS`) are dropped with a WARNING log. Keys outside
    the per-span allowlist are dropped with a DEBUG log. This is the
    sole entry point for setting span attributes in journalctl and
    journalctl-cloud -- never call ``span.set_attribute`` directly.

    Parameters
    ----------
    span_name:
        The canonical span name (e.g. ``"mcp.tool_call"``,
        ``"auth.bearer_introspect"``). Used to look up the allowlist.
        Unknown span names log a warning and behave as an empty
        allowlist (every key is dropped after the banned-key filter).
    span:
        The OpenTelemetry span to set attributes on. Duck-typed: any
        object with a ``set_attribute(key, value)`` method works.
    attrs:
        Dictionary of ``{key: value}`` to set.
    """
    allowlist = _get_allowlisted_attrs(span_name)
    if span_name not in SPAN_ALLOWLIST:
        logger.warning(
            "safe_set_attributes: unknown span_name %r -- applying global deny-list only",
            span_name,
        )

    for key, value in attrs.items():
        # Banned key check: exact match or any banned token as substring.
        if key in BANNED_KEYS:
            logger.warning(
                "Dropping banned span attribute %r on span %s",
                key,
                span_name,
            )
            continue
        banned_substring_hit = next((b for b in BANNED_KEYS if b in key), None)
        if banned_substring_hit is not None:
            logger.warning(
                "Dropping span attribute %r (contains banned token %r) on span %s",
                key,
                banned_substring_hit,
                span_name,
            )
            continue
        if key in allowlist:
            span.set_attribute(key, value)
        else:
            logger.debug(
                "Dropping non-allowlisted span attribute %r on span %s",
                key,
                span_name,
            )
