"""Regression tests for promoted Hydra types from gubbi + gubbi-cloud."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from gubbi_common.auth.hydra import (
    HydraError,
    HydraInvalidToken,
    HydraUnreachable,
    TokenClaims,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_claims(
    scope: str = "journal:read journal:write",
    exp: int = 1746500000,
) -> TokenClaims:
    return TokenClaims(sub=uuid4(), scope=scope, exp=exp)


# ---------------------------------------------------------------------------
# TokenClaims construction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_token_claims_construction() -> None:
    """TokenClaims accepts valid sub, scope, and exp fields."""
    cid = uuid4()
    claims = TokenClaims(sub=cid, scope="openapi", exp=1700000000)
    assert claims.sub == cid
    assert claims.scope == "openapi"
    assert claims.exp == 1700000000


# ---------------------------------------------------------------------------
# TokenClaims immutability (frozen dataclass)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_token_claims_is_frozen() -> None:
    """Mutation of a frozen TokenClaims raises FrozenInstanceError."""
    claims = _make_claims()
    with pytest.raises(FrozenInstanceError):
        claims.sub = uuid4()  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        claims.scope = "new-scope"  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        claims.exp = 999  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TokenClaims equality (value-based)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_token_claims_equality_value_based() -> None:
    """Two instances with identical fields compare equal."""
    cid = uuid4()
    a = TokenClaims(sub=cid, scope="journal:read", exp=1700000000)
    b = TokenClaims(sub=cid, scope="journal:read", exp=1700000000)
    assert a == b

    c = TokenClaims(sub=cid, scope="journal:write", exp=1700000000)
    assert a != c


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_hydra_unreachable_is_a_hydra_error() -> None:
    """HydraUnreachable is a subclass of HydraError."""
    err = HydraUnreachable("downstream is unreachable")
    assert isinstance(err, HydraError)
    assert isinstance(err, Exception)


@pytest.mark.unit
def test_hydra_invalid_token_is_a_hydra_error() -> None:
    """HydraInvalidToken is a subclass of HydraError."""
    err = HydraInvalidToken("inactive token")
    assert isinstance(err, HydraError)
    assert isinstance(err, Exception)


# ---------------------------------------------------------------------------
# Package-level re-export verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_all_four_symbols_importable_from_package() -> None:
    """All four promoted symbols are importable from gubbi_common.auth."""
    from gubbi_common.auth import (
        HydraError,
        HydraInvalidToken,
        HydraUnreachable,
        TokenClaims,
    )

    assert not issubclass(TokenClaims, BaseException)  # dataclass, not an Exception subclass
    assert issubclass(HydraError, BaseException)
    assert issubclass(HydraUnreachable, HydraError)
    assert issubclass(HydraInvalidToken, HydraError)


@pytest.mark.unit
def test_all_four_symbols_in___all__() -> None:
    """All four promoted symbols appear in gubbi_common.auth.__all__."""
    from gubbi_common.auth import __all__

    for name in ("HydraError", "HydraInvalidToken", "HydraUnreachable", "TokenClaims"):
        assert name in __all__, f"{name!r} missing from __all__"


# ---------------------------------------------------------------------------
# Exception instances carry messages
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_hydra_error_messages_propagate() -> None:
    """Exception subclasses forward message strings through base HydraError."""
    msg = "token was rejected"
    err = HydraInvalidToken(msg)
    assert str(err) == msg

    msg2 = "gateway timeout"
    err2 = HydraUnreachable(msg2)
    assert str(err2) == msg2
