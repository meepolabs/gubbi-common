"""Per-span attribute allowlist enforcement (DEC-070).

Hard rule: NO journal content -- and NO raw PII -- in spans, metrics, or
structured logs. This module is the **primary defense**: banned keys are
dropped at the span-builder layer before they ever reach the
exporter / batcher / sampler. Collector-side redact rules are
defense-in-depth, not the contract.

``safe_set_attributes(span_name, span, attrs, *, allowlist)`` silently drops any key
that:

1. Is not in the per-span allowlist.
2. Matches an entry in :data:`BANNED_KEYS` exactly, or contains any
   :data:`BANNED_KEYS` entry as a substring -- unless the key ends with a
   :data:`TRAILING_MODIFIERS` suffix and its stripped base does not contain
   any :data:`NEVER_EXEMPT_BASES` entry.

Unknown span names (not found in the injected ``allowlist`` dict) have
ALL attributes dropped and emit a single DEBUG log entry. Per-span
allowlists are OWNED by the caller -- this module no longer ships a
global ``SPAN_ALLOWLIST`` table.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Final

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Banned attribute keys
# ---------------------------------------------------------------------------
# Union of the deny-lists carried by journalctl and journalctl-cloud as of
# the migration into gubbi-common. Substring matching is applied: any
# attribute key containing one of these tokens is dropped, UNLESS the key
# ends with a TRAILING_MODIFIERS suffix whose stripped base does not
# contain any NEVER_EXEMPT_BASES term.
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
# Trailing-modifier exemption
# ---------------------------------------------------------------------------
# Attribute keys ending in any of these suffixes skip the BANNED_KEYS
# substring check, allowing hashed / counted / sized forms of otherwise-
# banned tokens (e.g. client_user_agent_hash, query_count, body_size)
# unless the stripped base contains a NEVER_EXEMPT_BASES term.
TRAILING_MODIFIERS: Final[tuple[str, ...]] = (
    "_hash",
    "_count",
    "_size",
    "_bytes",
    "_length",
    "_present",
    "_fp",
    "_id",
)

# Bases that are never exempt, even when followed by a trailing modifier.
# Example: password_hash, session_token_id, api_credential_fp are all
# still dropped because their stripped base contains one of these terms.
NEVER_EXEMPT_BASES: Final[tuple[str, ...]] = (
    "password",
    "secret",
    "token",
    "credential",
    "key",
)


def _is_banned(key: str) -> bool:
    """Return True if *key* is banned.

    Applies trailing-modifier exemption: if *key* ends with a
    :data:`TRAILING_MODIFIERS` suffix, the BANNED_KEYS substring check is
    skipped. However, if the stripped base contains any
    :data:`NEVER_EXEMPT_BASES` term, the key remains banned.
    """
    for modifier in TRAILING_MODIFIERS:
        if key.endswith(modifier):
            base = key[: -len(modifier)]
            return any(never_exempt in base for never_exempt in NEVER_EXEMPT_BASES)
    if key in BANNED_KEYS:
        return True
    return any(token in key for token in BANNED_KEYS)


def safe_set_attributes(
    span_name: str,
    span: Any,
    attrs: Mapping[str, Any],
    *,
    allowlist: Mapping[str, frozenset[str]],
) -> None:
    """Set attributes on *span*, dropping any banned or non-allowlisted key.

    Banned keys (exact match or substring match against
    :data:`BANNED_KEYS`) are dropped with a WARNING log. Keys outside
    the per-span allowlist are dropped with a DEBUG log. This is the
    sole entry point for setting span attributes in journalctl and
    journalctl-cloud -- never call ``span.set_attribute`` /
    ``span.set_attributes`` directly.

    Parameters
    ----------
    span_name:
        The canonical span name (e.g. ``"mcp.tool_call"``,
        ``"auth.bearer_introspect"``). Used to look up the allowlist.
        Unknown span names drop ALL attributes and emit one DEBUG log.
    span:
        The OpenTelemetry span to set attributes on. Calls
        ``span.set_attributes(dict)`` exactly once with the filtered
        result.
    attrs:
        Dictionary of ``{key: value}`` to set.
    allowlist:
        Per-span attribute allowlist injected by the caller. A mapping
        from span name to frozenset of allowed attribute keys.
    """
    allowed = allowlist.get(span_name)

    if allowed is None:
        logger.debug(
            "safe_set_attributes: unknown span_name %r -- dropping all attributes",
            span_name,
        )
        span.set_attributes({})
        return

    filtered: dict[str, Any] = {}
    dropped: list[str] = []
    for key, value in attrs.items():
        if key not in allowed:
            dropped.append(key)
            continue
        if _is_banned(key):
            logger.warning(
                "Dropping banned span attribute %r on span %s",
                key,
                span_name,
            )
            continue
        filtered[key] = value

    if dropped:
        logger.debug(
            "safe_set_attributes(%r): dropped non-allowlisted keys %s",
            span_name,
            dropped,
        )

    span.set_attributes(filtered)
