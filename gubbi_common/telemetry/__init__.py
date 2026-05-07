"""Telemetry primitives shared by gubbi and gubbi-cloud."""

from gubbi_common.telemetry.allowlist import (
    BANNED_KEYS,
    safe_set_attributes,
)
from gubbi_common.telemetry.logging import (
    StructuredLogFormatter,
    get_correlation_id,
    initialize_logger,
    reset_correlation_id,
    set_correlation_id,
)
from gubbi_common.telemetry.otel import (
    configure_otel,
    get_tracer,
)

# `_get_otel_ids` remains accessible via explicit
# `from gubbi_common.telemetry.logging import _get_otel_ids` for tests, but is
# not re-exported from this package nor listed in `__all__` because the
# leading underscore signals it as a private helper.
__all__ = [
    "BANNED_KEYS",
    "safe_set_attributes",
    "StructuredLogFormatter",
    "set_correlation_id",
    "reset_correlation_id",
    "get_correlation_id",
    "configure_otel",
    "get_tracer",
    "initialize_logger",
]
