"""Telemetry primitives shared by journalctl and journalctl-cloud."""

from gubbi_common.telemetry.allowlist import (
    BANNED_KEYS,
    safe_set_attributes,
)

__all__ = ["BANNED_KEYS", "safe_set_attributes"]
