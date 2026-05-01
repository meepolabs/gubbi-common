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

The journalctl repo enforces scope and passes ``required_scope`` on 403
responses. The journalctl-cloud gateway does not enforce scope today and
omits the parameter. Both call this single builder.
"""

from __future__ import annotations

__all__ = ["build_bearer_challenge"]


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
        Optional RFC 6750 error code. Common values: ``invalid_token``,
        ``insufficient_scope``, ``invalid_request``. Pass ``None`` for
        the no-credentials path so the field is omitted.
    resource_metadata_url:
        Optional URI of the OAuth protected-resource metadata document.
        Per RFC 9728 / MCP spec, MCP resources should include this so
        clients can discover the authorization server. May be absolute
        (``https://api.example.com/.well-known/oauth-protected-resource``)
        or relative (``/.well-known/oauth-protected-resource``).
    required_scope:
        Optional scope name the access token must carry. Use only on
        403 ``insufficient_scope`` responses where the resource enforces
        scope; omit for 401s.

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
