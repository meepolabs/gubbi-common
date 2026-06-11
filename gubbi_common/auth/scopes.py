"""Canonical OAuth scope vocabulary for the journal resource.

Single source of truth for the journal scope strings shared by the
cloud-api gateway and gubbi's own scope grants. Both sides MUST use
these constants so the vocabulary cannot fork: the gateway's
cookie-session scope assertion and gubbi's grant logic resolve to the
same literals.

``COOKIE_MODE_SCOPES`` is the space-delimited scope string the gateway
asserts for cookie-session (BFF) requests, which receive both read and
write access.
"""

from __future__ import annotations

SCOPE_READ = "journal:read"
SCOPE_WRITE = "journal:write"
COOKIE_MODE_SCOPES = f"{SCOPE_READ} {SCOPE_WRITE}"

__all__ = ["COOKIE_MODE_SCOPES", "SCOPE_READ", "SCOPE_WRITE"]
