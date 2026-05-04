"""RFC 6750 / RFC 9728 Bearer challenge builder.

Single source of truth for ``WWW-Authenticate: Bearer ...`` header values
emitted on 401 / 403 responses to MCP clients.

Per RFC 6750 sec 3:
* The ``error`` parameter is only included when an authentication attempt
  was made and failed (e.g. ``invalid_token``, ``insufficient_scope``).
  On a no-credentials challenge the field is omitted.
* The ``scope`` parameter (mapped here to ``required_scope``) names the
  scopes a successful access token must carry. Used by 403
  ``insufficient_scope`` responses; omitted for 401s and for endpoints
  that do not enforce scope.

Per RFC 9728 + MCP spec 2025-11-25:
* Protected MCP resources include ``resource_metadata=<URI>`` so clients
  can discover the OAuth protected-resource metadata document. The URI
  may be relative or absolute; callers decide which to emit.

The gubbi repo enforces scope and passes ``required_scope`` on 403
responses. The gubbi-cloud gateway does not enforce scope today and
omits the parameter. Both call this single builder.

Inputs are validated to prevent header injection (response splitting via
CR/LF, quote-injection via `"` or `\\`). RFC 7230 forbids CR / LF / NUL in
header values; RFC 6750 quoted-string parameters cannot contain
unescaped `"` or `\\`. Callers compose challenge values, sometimes from
request data (for downstream forks of this AGPL library); silently
emitting malformed values would be a security bug.
"""

from __future__ import annotations

import re

__all__ = ["build_bearer_challenge"]


# RFC 7230 token grammar -- the set of legal characters in an unquoted
# header parameter value. Used here to constrain the OAuth ``error`` code
# (which must be a token per RFC 6750 sec 3).
_TOKEN_RE: re.Pattern[str] = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# RFC 6749 sec 3.3 scope grammar (single scope-token).
# scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
_SCOPE_TOKEN_RE: re.Pattern[str] = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")

# Multi-scope value: space-separated scope-tokens. RFC 6749 ABNF for
# ``scope`` itself: scope = scope-token *( SP scope-token ).
_SCOPE_RE: re.Pattern[str] = re.compile(
    r"^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$"
)

# Characters forbidden anywhere in any input field:
#   - CR / LF / NUL and other C0 controls (response splitting / log
#     injection).
#   - DEL (\x7f).
#   - `"` and `\\` (would break the RFC 6750 quoted-string framing).
_FORBIDDEN_RE: re.Pattern[str] = re.compile(r'[\x00-\x1f\x7f"\\]')


def _reject_forbidden(name: str, value: str) -> None:
    if _FORBIDDEN_RE.search(value):
        raise ValueError(
            f"{name} contains a forbidden character "
            "(control, DEL, double-quote, or backslash) -- "
            "would corrupt the WWW-Authenticate header"
        )


def build_bearer_challenge(
    error: str | None = None,
    resource_metadata_url: str | None = None,
    *,
    required_scope: str | None = None,
) -> str:
    """Return a ``WWW-Authenticate`` Bearer header value.

    Parameters
    ----------
    error:
        Optional RFC 6750 error code. Must be an RFC 7230 token
        (``[!#$%&'*+\\-.^_`|~0-9A-Za-z]+``). Common values:
        ``invalid_token``, ``insufficient_scope``, ``invalid_request``.
        Pass ``None`` for the no-credentials path so the field is
        omitted.
    resource_metadata_url:
        Optional URI of the OAuth protected-resource metadata document.
        Per RFC 9728 / MCP spec, MCP resources should include this so
        clients can discover the authorization server. Must start with
        ``/`` (relative) or ``https://`` (absolute). HTTP is not
        accepted -- the OAuth metadata document must be fetched over
        TLS.
    required_scope:
        Optional scope name(s) the access token must carry. Must conform
        to RFC 6749 scope grammar (one or more scope-tokens separated by
        single spaces). Use only on 403 ``insufficient_scope`` responses
        where the resource enforces scope; omit for 401s.

    Raises
    ------
    ValueError
        If any input contains a forbidden character (CR, LF, NUL, other
        C0 control, DEL, `"`, or `\\`); if ``error`` violates RFC 7230
        token grammar; if ``required_scope`` violates RFC 6749 scope
        grammar; or if ``resource_metadata_url`` does not start with
        ``/`` or ``https://``.

    Returns
    -------
    str
        ``Bearer`` followed by zero or more comma-separated
        ``key="value"`` parameters. Example outputs:

        * ``Bearer resource_metadata="/.well-known/..."``
        * ``Bearer error="invalid_token", resource_metadata="..."``
        * ``Bearer error="insufficient_scope",
          required_scope="journal:write", resource_metadata="..."``

        Empty parameter list yields the literal ``"Bearer"`` (caller
        responsibility -- callers always pass at least one of error or
        resource_metadata_url in practice).
    """
    if error is not None:
        _reject_forbidden("error", error)
        if not _TOKEN_RE.match(error):
            raise ValueError(
                f"error={error!r} is not a valid RFC 7230 token -- "
                "must consist of token characters only"
            )

    if required_scope is not None:
        _reject_forbidden("required_scope", required_scope)
        if not _SCOPE_RE.match(required_scope):
            raise ValueError(f"required_scope={required_scope!r} violates RFC 6749 scope grammar")

    if resource_metadata_url is not None:
        _reject_forbidden("resource_metadata_url", resource_metadata_url)
        if not (
            resource_metadata_url.startswith("/") or resource_metadata_url.startswith("https://")
        ):
            raise ValueError(
                f"resource_metadata_url={resource_metadata_url!r} "
                "must start with '/' (relative) or 'https://' (absolute)"
            )

    parts: list[str] = []
    if error is not None:
        parts.append(f'error="{error}"')
    if required_scope is not None:
        parts.append(f'required_scope="{required_scope}"')
    if resource_metadata_url is not None:
        parts.append(f'resource_metadata="{resource_metadata_url}"')
    if not parts:
        return "Bearer"
    return "Bearer " + ", ".join(parts)
