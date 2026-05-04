"""HMAC-SHA256 signature for the gateway -> internal-upstream handoff.

Threat model
------------
The public-facing gateway (cloud-api) authenticates the end user, then
forwards the request to an internal upstream (gubbi) over a private
network. The upstream cannot re-run the user's OAuth flow, so it trusts
the gateway-supplied identity headers (``X-Auth-User``, ``X-Auth-Scopes``).
A shared secret signs those headers plus method + path + a timestamp so
that a compromised internal host (or a misrouted request from another
internal service) cannot forge identity. The signature binds the request
identity, method, and path. It does NOT bind the request body, query
string, or response. It does NOT replace TLS -- it complements network
isolation. Both signer and verifier MUST pin the same gubbi-common
version; the canonical input format is versioned by
``GATEWAY_CONTRACT_VERSION`` so a contract change is observable.
"""

from __future__ import annotations

import hmac
import re
from datetime import UTC, datetime
from hashlib import sha256

__all__ = [
    "GATEWAY_CONTRACT_VERSION",
    "MAX_SKEW_SECONDS",
    "FutureSignatureError",
    "MalformedTimestampError",
    "MismatchedSignatureError",
    "SignatureError",
    "StaleSignatureError",
    "build_signature",
    "verify_signature",
]


GATEWAY_CONTRACT_VERSION: int = 1
MAX_SKEW_SECONDS: int = 30


# ISO 8601 ``YYYY-MM-DDTHH:MM:SSZ`` UTC, no fractional seconds, ``Z`` suffix.
_TIMESTAMP_RE: re.Pattern[str] = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# ``|`` is the canonical-input field separator. Any field containing it
# would make the canonical string ambiguous (canonicalisation-confusion):
# user_id="a|b" + scopes="c" encodes identically to user_id="a" +
# scopes="b|c". Reject up front in both signer and verifier so a
# downstream consumer with non-UUID identifiers cannot accidentally ship
# a vulnerable contract.
_FIELD_SEPARATOR: str = "|"


class SignatureError(ValueError):
    """Base class for gateway-signature verification failures.

    The subclasses identify *why* verification failed so callers can
    log structured fields, but a verifier in a security-sensitive path
    typically just catches ``SignatureError`` and returns 401.
    """


class StaleSignatureError(SignatureError):
    """Timestamp is older than ``now - max_skew_seconds``."""


class FutureSignatureError(SignatureError):
    """Timestamp is newer than ``now + max_skew_seconds``."""


class MalformedTimestampError(SignatureError):
    """Timestamp is not the documented ISO 8601 UTC ``Z``-suffixed form."""


class MismatchedSignatureError(SignatureError):
    """Recomputed HMAC does not match the supplied signature."""


def _reject_field_separator(
    user_id: str,
    scopes: str,
    timestamp: str,
    method: str,
    path: str,
) -> None:
    """Refuse any input containing the canonical-input field separator.

    Both signer and verifier go through this guard so a tampered-with
    field cannot cross-decode into a different canonical input.
    """
    for name, value in (
        ("user_id", user_id),
        ("scopes", scopes),
        ("timestamp", timestamp),
        ("method", method),
        ("path", path),
    ):
        if _FIELD_SEPARATOR in value:
            raise ValueError(
                f"{name} contains the canonical-input field separator "
                f"({_FIELD_SEPARATOR!r}); reject to avoid "
                "canonicalisation confusion"
            )


def _canonical_input(
    user_id: str,
    scopes: str,
    timestamp: str,
    method: str,
    path: str,
) -> bytes:
    return (f"{GATEWAY_CONTRACT_VERSION}|{user_id}|{scopes}|{timestamp}|{method}|{path}").encode()


def _parse_timestamp(timestamp: str) -> datetime:
    if not _TIMESTAMP_RE.match(timestamp):
        raise MalformedTimestampError(
            f"timestamp={timestamp!r} is not ISO 8601 'YYYY-MM-DDTHH:MM:SSZ' UTC"
        )
    try:
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise MalformedTimestampError(
            f"timestamp={timestamp!r} is not a valid UTC datetime: {exc}"
        ) from exc


def build_signature(
    secret: bytes,
    user_id: str,
    scopes: str,
    timestamp: str,
    method: str,
    path: str,
) -> str:
    """Return hex-encoded HMAC-SHA256 over the canonical input.

    The canonical input is::

        f"{GATEWAY_CONTRACT_VERSION}|{user_id}|{scopes}|{timestamp}|{method}|{path}"

    encoded as UTF-8. ``timestamp`` is an ISO 8601 ``YYYY-MM-DDTHH:MM:SSZ``
    UTC string (no fractional seconds, ``Z`` suffix); the verifier
    validates that format. ``scopes`` is the space-separated scope-token
    list as it appears in the ``X-Auth-Scopes`` header, normalised
    (sorted whitespace-deduped) by the caller before hashing. Method is
    uppercase; path is the request path including leading ``/`` (no
    query string).

    None of ``user_id``, ``scopes``, ``timestamp``, ``method``, or
    ``path`` may contain the canonical-input field separator ``|``;
    fields containing it raise ``ValueError`` to prevent
    canonicalisation-confusion ambiguity.
    """
    _reject_field_separator(user_id, scopes, timestamp, method, path)
    canonical = _canonical_input(user_id, scopes, timestamp, method, path)
    return hmac.new(secret, canonical, sha256).hexdigest()


def verify_signature(
    secret: bytes,
    expected_signature: str,
    user_id: str,
    scopes: str,
    timestamp: str,
    method: str,
    path: str,
    *,
    now: datetime | None = None,
    max_skew_seconds: int = MAX_SKEW_SECONDS,
) -> None:
    """Raise ``SignatureError`` if the signature does not verify.

    Returns ``None`` on success.

    Validates the timestamp format BEFORE computing the HMAC, so a
    malformed timestamp raises ``MalformedTimestampError`` rather than
    being misreported as a mismatched signature. Skew checks are
    performed before the constant-time HMAC comparison; this is safe
    because timestamps are public (sent on the wire alongside the
    signature) -- the secret is never involved in the skew decision.

    Inputs containing the canonical-input field separator ``|`` raise
    ``ValueError`` (canonicalisation-confusion guard).

    ``now`` is for testing; production callers omit it.
    """
    _reject_field_separator(user_id, scopes, timestamp, method, path)
    parsed = _parse_timestamp(timestamp)

    current = now if now is not None else datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)

    delta = (current - parsed).total_seconds()
    if delta > max_skew_seconds:
        raise StaleSignatureError(
            f"timestamp is {delta:.0f}s old; max allowed skew is {max_skew_seconds}s"
        )
    if delta < -max_skew_seconds:
        raise FutureSignatureError(
            f"timestamp is {-delta:.0f}s in the future; "
            f"max allowed forward skew is {max_skew_seconds}s"
        )

    canonical = _canonical_input(user_id, scopes, timestamp, method, path)
    computed = hmac.new(secret, canonical, sha256).hexdigest()
    if not hmac.compare_digest(computed, expected_signature):
        raise MismatchedSignatureError("signature does not match canonical input")
