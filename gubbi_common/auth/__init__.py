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
from gubbi_common.auth.prm import PRMUrlError, build_prm_metadata_url

__all__ = [
    "GATEWAY_CONTRACT_VERSION",
    "MAX_SKEW_SECONDS",
    "FutureSignatureError",
    "HydraError",
    "HydraInvalidToken",
    "HydraUnreachable",
    "MalformedTimestampError",
    "MismatchedSignatureError",
    "PRMUrlError",
    "SignatureError",
    "StaleSignatureError",
    "TokenClaims",
    "build_bearer_challenge",
    "build_prm_metadata_url",
    "build_signature",
    "verify_signature",
]
