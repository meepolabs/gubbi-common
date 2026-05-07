"""Hydra OAuth 2.0 introspection data contract.

This module holds the data types shared across gubbi and gubbi-cloud for
token introspection with ORY Hydra. The definitions are byte-identical in
both consumer repos; this canonical copy serves as the source of truth so
that downstream consumers import from a single location rather than each
repo maintaining its own copy.

Exported symbols: ``TokenClaims`` (frozen dataclass), ``HydraError``,
``HydraUnreachable``, ``HydraInvalidToken`` (exception hierarchy).
The introspector logic and cache protocol stay per-repo -- this module
carries only the cross-cutting shapes.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

__all__ = [
    "HydraError",
    "HydraInvalidToken",
    "HydraUnreachable",
    "TokenClaims",
]


@dataclass(frozen=True)
class TokenClaims:
    sub: UUID
    scope: str  # raw space-delimited scope string from Hydra
    exp: int  # unix timestamp


class HydraError(Exception):
    pass


class HydraUnreachable(HydraError):
    pass


class HydraInvalidToken(HydraError):
    pass
