"""Auth primitives shared by gubbi and gubbi-cloud."""

from gubbi_common.auth.bearer_challenge import build_bearer_challenge
from gubbi_common.auth.gateway_signature import (
    GATEWAY_CONTRACT_VERSION,
    MAX_SKEW_SECONDS,
    FutureSignatureError,
    MalformedTimestampError,
    MismatchedSignatureError,
    SignatureError,
    StaleSignatureError,
    build_signature,
    verify_signature,
)

__all__ = [
    "GATEWAY_CONTRACT_VERSION",
    "MAX_SKEW_SECONDS",
    "FutureSignatureError",
    "MalformedTimestampError",
    "MismatchedSignatureError",
    "SignatureError",
    "StaleSignatureError",
    "build_bearer_challenge",
    "build_signature",
    "verify_signature",
]
