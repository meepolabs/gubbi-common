"""Tests for the gateway HMAC-SHA256 signature utility."""

from __future__ import annotations

import hmac as _hmac_module
from datetime import UTC, datetime, timedelta

import pytest

from gubbi_common.auth import gateway_signature
from gubbi_common.auth.gateway_signature import (
    GATEWAY_CONTRACT_VERSION,
    MAX_SKEW_SECONDS,
    FutureSignatureError,
    MalformedTimestampError,
    MismatchedSignatureError,
    StaleSignatureError,
    build_signature,
    verify_signature,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_SECRET = b"super-secret-key-bytes"
_USER = "user_123"
_SCOPES = "journal:read journal:write"
_TS = "2026-05-02T10:30:00Z"
_METHOD = "POST"
_PATH = "/api/v1/journal"

_NOW = datetime(2026, 5, 2, 10, 30, 0, tzinfo=UTC)


def _sig(**overrides: str) -> str:
    fields = {
        "user_id": _USER,
        "scopes": _SCOPES,
        "timestamp": _TS,
        "method": _METHOD,
        "path": _PATH,
    }
    fields.update(overrides)
    return build_signature(_SECRET, **fields)


# ---------------------------------------------------------------------------
# build_signature
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_build_signature_is_deterministic() -> None:
    a = build_signature(_SECRET, _USER, _SCOPES, _TS, _METHOD, _PATH)
    b = build_signature(_SECRET, _USER, _SCOPES, _TS, _METHOD, _PATH)
    assert a == b
    assert len(a) == 64  # hex sha256


@pytest.mark.unit
def test_build_signature_changes_with_user_id() -> None:
    assert _sig() != _sig(user_id="other_user")


@pytest.mark.unit
def test_build_signature_changes_with_scopes() -> None:
    assert _sig() != _sig(scopes="journal:read")


@pytest.mark.unit
def test_build_signature_changes_with_timestamp() -> None:
    assert _sig() != _sig(timestamp="2026-05-02T10:30:01Z")


@pytest.mark.unit
def test_build_signature_changes_with_method() -> None:
    assert _sig() != _sig(method="GET")


@pytest.mark.unit
def test_build_signature_changes_with_path() -> None:
    assert _sig() != _sig(path="/api/v1/other")


# ---------------------------------------------------------------------------
# verify_signature -- happy path / round trip
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_round_trip_returns_none() -> None:
    sig = _sig()
    result = verify_signature(_SECRET, sig, _USER, _SCOPES, _TS, _METHOD, _PATH, now=_NOW)
    assert result is None


# ---------------------------------------------------------------------------
# verify_signature -- mismatches
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_wrong_secret_raises_mismatched() -> None:
    sig = build_signature(b"wrong-secret", _USER, _SCOPES, _TS, _METHOD, _PATH)
    with pytest.raises(MismatchedSignatureError):
        verify_signature(_SECRET, sig, _USER, _SCOPES, _TS, _METHOD, _PATH, now=_NOW)


@pytest.mark.unit
def test_tampered_user_id_raises_mismatched() -> None:
    sig = _sig()
    with pytest.raises(MismatchedSignatureError):
        verify_signature(_SECRET, sig, "attacker", _SCOPES, _TS, _METHOD, _PATH, now=_NOW)


@pytest.mark.unit
def test_empty_method_does_not_short_circuit() -> None:
    # Build with empty method, verify with the real method -- must mismatch,
    # not silently succeed.
    forged = build_signature(_SECRET, _USER, _SCOPES, _TS, "", _PATH)
    with pytest.raises(MismatchedSignatureError):
        verify_signature(_SECRET, forged, _USER, _SCOPES, _TS, _METHOD, _PATH, now=_NOW)


@pytest.mark.unit
def test_lowercase_method_mismatches_uppercase() -> None:
    forged = build_signature(_SECRET, _USER, _SCOPES, _TS, "post", _PATH)
    with pytest.raises(MismatchedSignatureError):
        verify_signature(_SECRET, forged, _USER, _SCOPES, _TS, _METHOD, _PATH, now=_NOW)


# ---------------------------------------------------------------------------
# verify_signature -- skew
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_stale_timestamp_raises() -> None:
    sig = _sig()
    later = _NOW + timedelta(seconds=31)
    with pytest.raises(StaleSignatureError):
        verify_signature(_SECRET, sig, _USER, _SCOPES, _TS, _METHOD, _PATH, now=later)


@pytest.mark.unit
def test_future_timestamp_raises() -> None:
    sig = _sig()
    earlier = _NOW - timedelta(seconds=31)
    with pytest.raises(FutureSignatureError):
        verify_signature(_SECRET, sig, _USER, _SCOPES, _TS, _METHOD, _PATH, now=earlier)


@pytest.mark.unit
def test_within_tolerance_past_skew_succeeds() -> None:
    sig = _sig()
    later = _NOW + timedelta(seconds=25)
    assert verify_signature(_SECRET, sig, _USER, _SCOPES, _TS, _METHOD, _PATH, now=later) is None


@pytest.mark.unit
def test_within_tolerance_future_skew_succeeds() -> None:
    sig = _sig()
    earlier = _NOW - timedelta(seconds=25)
    assert verify_signature(_SECRET, sig, _USER, _SCOPES, _TS, _METHOD, _PATH, now=earlier) is None


@pytest.mark.unit
def test_exact_max_skew_boundary_succeeds() -> None:
    sig = _sig()
    later = _NOW + timedelta(seconds=MAX_SKEW_SECONDS)
    assert verify_signature(_SECRET, sig, _USER, _SCOPES, _TS, _METHOD, _PATH, now=later) is None


# ---------------------------------------------------------------------------
# verify_signature -- malformed timestamp
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_ts",
    [
        "not-iso",
        "2026-05-02T10:30:00",  # no Z
        "2026-05-02T10:30:00.123Z",  # fractional seconds
        "2026-05-02T10:30:00+00:00",  # tz offset, not Z
        "",
        "2026-05-02 10:30:00Z",  # space instead of T
        "2026-13-02T10:30:00Z",  # invalid month
    ],
)
def test_malformed_timestamp_raises(bad_ts: str) -> None:
    # Sign with the (also malformed) timestamp so the only possible failure
    # is the format check, not a HMAC mismatch.
    sig = build_signature(_SECRET, _USER, _SCOPES, bad_ts, _METHOD, _PATH)
    with pytest.raises(MalformedTimestampError):
        verify_signature(_SECRET, sig, _USER, _SCOPES, bad_ts, _METHOD, _PATH, now=_NOW)


@pytest.mark.unit
def test_malformed_timestamp_checked_before_hmac() -> None:
    # Even with a totally wrong signature, a malformed timestamp must surface
    # as MalformedTimestampError (not MismatchedSignatureError), so that
    # operators see the real cause.
    with pytest.raises(MalformedTimestampError):
        verify_signature(
            _SECRET,
            "deadbeef" * 8,
            _USER,
            _SCOPES,
            "not-iso",
            _METHOD,
            _PATH,
            now=_NOW,
        )


# ---------------------------------------------------------------------------
# Constants and constant-time comparison
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_max_skew_seconds_constant() -> None:
    assert MAX_SKEW_SECONDS == 30


@pytest.mark.unit
def test_gateway_contract_version_is_one() -> None:
    assert GATEWAY_CONTRACT_VERSION == 1


@pytest.mark.unit
def test_contract_version_participates_in_canonical_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sig_v1 = _sig()
    monkeypatch.setattr(gateway_signature, "GATEWAY_CONTRACT_VERSION", 99)
    sig_v99 = build_signature(_SECRET, _USER, _SCOPES, _TS, _METHOD, _PATH)
    assert sig_v1 != sig_v99


# ---------------------------------------------------------------------------
# Canonicalisation-confusion guard (pipe rejection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "field",
    ["user_id", "scopes", "timestamp", "method", "path"],
)
def test_build_signature_rejects_pipe_in_any_field(field: str) -> None:
    with pytest.raises(ValueError, match="canonicalisation"):
        _sig(**{field: "value|with|pipe"})


@pytest.mark.unit
@pytest.mark.parametrize(
    "field",
    ["user_id", "scopes", "timestamp", "method", "path"],
)
def test_verify_signature_rejects_pipe_in_any_field(field: str) -> None:
    sig = _sig()
    fields = {
        "user_id": _USER,
        "scopes": _SCOPES,
        "timestamp": _TS,
        "method": _METHOD,
        "path": _PATH,
    }
    fields[field] = "value|with|pipe"
    with pytest.raises(ValueError, match="canonicalisation"):
        verify_signature(_SECRET, sig, **fields, now=_NOW)


# ---------------------------------------------------------------------------
# Constant-time comparison
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_verify_uses_constant_time_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Confirm that hmac.compare_digest from the hmac module is the comparator
    # used by verify_signature -- swap it out and observe the swap is hit.
    calls: list[tuple[str, str]] = []
    real_compare = _hmac_module.compare_digest

    def _spy(a: str | bytes, b: str | bytes) -> bool:
        calls.append((str(a), str(b)))
        return real_compare(a, b)

    monkeypatch.setattr(gateway_signature.hmac, "compare_digest", _spy)
    sig = _sig()
    verify_signature(_SECRET, sig, _USER, _SCOPES, _TS, _METHOD, _PATH, now=_NOW)
    assert len(calls) == 1
