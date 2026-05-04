"""Per-span attribute allowlist enforcement (DEC-070).

Hard rule: NO journal content -- and NO raw PII -- in spans, metrics, or
structured logs. This module is the **primary defense**: banned keys are
dropped at the span-builder layer before they ever reach the
exporter / batcher / sampler. Collector-side redact rules are
defense-in-depth, not the contract.

``safe_set_attributes(span_name, span, attrs, *, allowlist)`` silently drops any key
that:

1. Is not in the per-span allowlist.
2. Contains an entry from :data:`NEVER_EXEMPT_BASES` as a substring.
3. Matches an entry in :data:`BANNED_KEYS` exactly, or contains any
   :data:`BANNED_KEYS` entry as a substring -- unless the key ends with a
   :data:`DERIVATIVE_MODIFIERS` suffix (`_hash`, `_count`, `_size`,
   `_bytes`, `_len`, `_fp`). Those suffixes are structurally privacy-safe
   (a hash / count / size cannot carry the underlying value); other
   suffixes (`_id`, `_present`) can reveal or carry the value and so are
   NOT exempt.

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
# Union of the deny-lists carried by gubbi and gubbi-cloud as of
# the migration into gubbi-common. Substring matching is applied: any
# attribute key containing one of these tokens is dropped, UNLESS the key
# ends with a DERIVATIVE_MODIFIERS suffix (and its base is not in
# NEVER_EXEMPT_BASES).
BANNED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "address",
        "body",
        "completion",
        "content",
        "email",
        "ip_address",
        "messages",
        "password",
        "phone",
        "prompt",
        "query",
        "reasoning",
        "response_text",
        "search_query",
        "summary",
        "user_agent",
    }
)


# ---------------------------------------------------------------------------
# Derivative-suffix exemption
# ---------------------------------------------------------------------------
# Attribute keys ending in any of these suffixes describe a *derivative*
# quantity of the underlying value (a sha256 digest, a count, a size in
# bytes / chars, a fingerprint). They are structurally privacy-safe: the
# suffix's grammar cannot encode the original value.
#
# Notably absent: `_id` and `_present`. ``email_id`` could itself be PII
# (a stable per-email identifier joinable to the email), and ``_present``
# carries a one-bit signal that is still attributable to a user. Both
# now flow through the BANNED_KEYS substring check.
DERIVATIVE_MODIFIERS: Final[frozenset[str]] = frozenset(
    {
        "_hash",
        "_count",
        "_size",
        "_len",
        "_fp",
        "_bytes",
    }
)

# Bases whose presence anywhere in a key bans it unconditionally, even
# with a derivative suffix. Example: `password_hash`, `session_token_id`,
# `api_credential_fp` are all dropped. The intent: a hashed password is
# still a credential, and credential-shaped tokens should never appear
# in telemetry under any guise.
NEVER_EXEMPT_BASES: Final[tuple[str, ...]] = (
    "password",
    "secret",
    "token",
    "credential",
    "key",
)


def _is_banned(key: str) -> bool:
    """Return True if *key* must be dropped from span attributes.

    Order:
    1. NEVER_EXEMPT_BASES is checked first -- credential-shaped tokens
       are banned even with a derivative suffix (``password_hash`` is
       still a credential).
    2. A trailing :data:`DERIVATIVE_MODIFIERS` suffix exempts the key
       from the BANNED_KEYS substring check.
    3. Otherwise the key is banned if it equals or contains any
       :data:`BANNED_KEYS` entry as a substring.
    """
    if any(never in key for never in NEVER_EXEMPT_BASES):
        return True
    if any(key.endswith(suffix) for suffix in DERIVATIVE_MODIFIERS):
        return False
    return key in BANNED_KEYS or any(token in key for token in BANNED_KEYS)


def safe_set_attributes(
    span_name: str,
    span: Any,
    attrs: Mapping[str, Any],
    *,
    allowlist: Mapping[str, frozenset[str]],
) -> None:
    """Set attributes on *span*, dropping any banned or non-allowlisted key.

    Banned keys (exact match or substring match against
    :data:`BANNED_KEYS`, modulo :data:`DERIVATIVE_MODIFIERS` exemption)
    are dropped with a WARNING log. Keys outside the per-span allowlist
    are dropped with a DEBUG log. This is the sole entry point for
    setting span attributes in gubbi and gubbi-cloud -- never
    call ``span.set_attribute`` / ``span.set_attributes`` directly.

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
