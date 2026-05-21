"""Shared constants for the gubbi family of packages.

Single source of truth for literal values that would otherwise be
duplicated across gubbi (MCP server) and gubbi-cloud (gateway). Lifting
a constant here removes the lockstep hazard where two repos must be
updated together whenever the value changes.
"""

from __future__ import annotations

# Public-facing documentation URL surfaced as the ``resource_documentation``
# field of the OAuth Protected Resource Metadata document (RFC 9728).
# Both consumers (gubbi + gubbi-cloud) emit it in their
# ``/.well-known/oauth-protected-resource[/mcp]`` payloads, so the literal
# lives here to keep them in sync when the docs URL moves.
RESOURCE_DOCUMENTATION_URL: str = "https://gubbi.ai/docs/mcp"


__all__ = ["RESOURCE_DOCUMENTATION_URL"]
