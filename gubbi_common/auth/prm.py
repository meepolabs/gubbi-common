"""RFC 9728 Protected Resource Metadata URL helpers.

Single source of truth for how cloud-api and gubbi compute the PRM
metadata URL from a resource URL. Both sides MUST produce the same
absolute URL when they advertise it (WWW-Authenticate challenges,
discovery routes, OAuth audience claims).

Per RFC 9728 the metadata URL is
``https://<resource-host>/.well-known/oauth-protected-resource[/<resource-path>]``.
The legacy cutover form (DEC-083) appends ``/mcp`` to the path; the
canonical form omits it. ``legacy_suffix=True`` is the default through
the cutover window; flipping the default to ``False`` is tracked as a
backlog item ``prm-legacy-suffix-cutover``.

Promoting this helper to gubbi-common closes C-009 (PRM URL coherence
broken across cloud-api and gubbi): the formula was duplicated across
at least four call sites with subtly different concatenation, no shared
helper. Both consumers depend on this single implementation.
"""

from __future__ import annotations

from urllib.parse import urlparse

__all__ = ["PRMUrlError", "build_prm_metadata_url"]

_CANONICAL_PATH = "/.well-known/oauth-protected-resource"
# DEC-083 cutover compat; remove after Q3 telemetry confirms zero
# legacy-suffix clients in the wild. Flip via ``legacy_suffix=False``
# at every call site and then remove this constant.
_LEGACY_SUFFIX = "/mcp"


class PRMUrlError(ValueError):
    """Raised when ``resource_url`` is not an absolute http(s) URL."""


def build_prm_metadata_url(resource_url: str, *, legacy_suffix: bool = True) -> str:
    """Return the absolute PRM metadata URL for a given resource URL.

    The canonical form is ``<origin>/.well-known/oauth-protected-resource``.
    When ``legacy_suffix=True`` (the default) the cutover-form
    ``<origin>/.well-known/oauth-protected-resource/mcp`` is returned for
    backwards-compat with pre-DEC-083 clients. The default flips to
    ``False`` after the cutover window closes (tracked in backlog).

    Trailing slashes on ``resource_url`` are normalised away (only the
    scheme and netloc are used to derive the origin), so
    ``"https://mcp.gubbi.ai"`` and ``"https://mcp.gubbi.ai/"`` produce
    the same output.

    Parameters
    ----------
    resource_url:
        Absolute http(s) URL identifying the protected resource. The
        path component (if any) is discarded; only ``<scheme>://<netloc>``
        contributes to the result.
    legacy_suffix:
        When ``True`` (default), append ``/mcp`` after the canonical
        ``.well-known`` path for DEC-083 cutover compat. When ``False``,
        return the bare canonical form.

    Raises
    ------
    PRMUrlError
        If ``resource_url`` is not an absolute http(s) URL (no scheme,
        no netloc, or scheme other than http/https).

    Returns
    -------
    str
        The absolute PRM metadata URL.
    """
    parsed = urlparse(resource_url)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise PRMUrlError(f"resource_url must be absolute http(s) URL: {resource_url!r}")
    # Use ``hostname`` + ``port`` rather than raw ``netloc`` so any
    # ``user:pass@`` userinfo in the input URL is stripped before the
    # origin lands in WWW-Authenticate challenges, discovery JSON, or
    # OAuth audience claims (any of which may be logged or returned to
    # untrusted clients). RFC 6454 origin is ``scheme://host[:port]`` --
    # userinfo is explicitly excluded.
    host = parsed.hostname
    if not host:
        raise PRMUrlError(f"resource_url must include a host: {resource_url!r}")
    # ``parsed.port`` raises ValueError for malformed ports
    # (e.g. ``https://host:99999`` or ``https://host:abc``). Wrap so the
    # caller-visible exception type matches the docstring contract.
    try:
        port = parsed.port
    except ValueError as exc:
        raise PRMUrlError(f"resource_url has malformed port: {resource_url!r}") from exc
    port_part = f":{port}" if port else ""
    origin = f"{parsed.scheme}://{host}{port_part}"
    suffix = _LEGACY_SUFFIX if legacy_suffix else ""
    return f"{origin}{_CANONICAL_PATH}{suffix}"
