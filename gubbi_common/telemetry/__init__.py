"""Telemetry primitives shared by gubbi and gubbi-cloud."""

from gubbi_common.telemetry.allowlist import (
    BANNED_KEYS,
    safe_set_attributes,
)

__all__ = ["BANNED_KEYS", "safe_set_attributes"]
