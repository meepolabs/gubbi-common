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
from gubbi_common.auth.hydra import (
    HydraError,
    HydraInvalidToken,
    HydraUnreachable,
    TokenClaims,
)

__all__ = [
    "GATEWAY_CONTRACT_VERSION",
    "FutureSignatureError",
    "HydraError",
    "HydraInvalidToken",
    "HydraUnreachable",
    "MAX_SKEW_SECONDS",
    "MalformedTimestampError",
    "MismatchedSignatureError",
    "SignatureError",
    "StaleSignatureError",
    "TokenClaims",
    "build_bearer_challenge",
    "build_signature",
    "verify_signature",
]
