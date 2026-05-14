"""Tests for the canonical correlation_id module (B5 Q1)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from gubbi_common.correlation import (
    CorrelationContext,
    cid_from_scope,
    get_correlation_id,
    reset_correlation_id,
    set_correlation_id,
)


class TestCorrelationContextDataclass:
    """The canonical envelope type that crosses the gateway boundary."""

    @pytest.mark.unit
    def test_construct_with_correlation_id(self) -> None:
        # Arrange
        cid = "abc-123"

        # Act
        ctx = CorrelationContext(correlation_id=cid)

        # Assert
        assert ctx.correlation_id == cid

    @pytest.mark.unit
    def test_frozen_dataclass_rejects_mutation(self) -> None:
        ctx = CorrelationContext(correlation_id="x")
        with pytest.raises(FrozenInstanceError):
            ctx.correlation_id = "y"  # type: ignore[misc]

    @pytest.mark.unit
    def test_two_instances_with_same_id_are_equal(self) -> None:
        a = CorrelationContext(correlation_id="abc")
        b = CorrelationContext(correlation_id="abc")
        assert a == b
        assert hash(a) == hash(b)


class TestCidFromScope:
    """Centralised ASGI-scope correlation_id extraction."""

    @pytest.mark.unit
    def test_returns_value_when_header_present(self) -> None:
        scope = {"headers": [(b"x-correlation-id", b"my-cid-123")]}
        assert cid_from_scope(scope) == "my-cid-123"

    @pytest.mark.unit
    def test_returns_empty_string_when_header_absent(self) -> None:
        scope = {"headers": [(b"content-type", b"application/json")]}
        assert cid_from_scope(scope) == ""

    @pytest.mark.unit
    def test_returns_empty_string_when_headers_missing(self) -> None:
        assert cid_from_scope({}) == ""

    @pytest.mark.unit
    def test_picks_first_correlation_header_when_repeated(self) -> None:
        # Pathological multi-header case -- the first value wins.
        scope = {
            "headers": [
                (b"x-correlation-id", b"first"),
                (b"x-correlation-id", b"second"),
            ]
        }
        assert cid_from_scope(scope) == "first"

    @pytest.mark.unit
    def test_handles_invalid_utf8_gracefully(self) -> None:
        scope = {"headers": [(b"x-correlation-id", b"\xff\xfe-bad")]}
        # Should not raise; returns empty string on decode failure.
        result = cid_from_scope(scope)
        assert isinstance(result, str)


class TestContextVarReExports:
    """gubbi_common.correlation re-exports the canonical contextvar API."""

    @pytest.mark.unit
    def test_set_get_reset_roundtrip(self) -> None:
        # Capture prior state to avoid leaking across tests.
        token = set_correlation_id("test-cid-roundtrip")
        try:
            assert get_correlation_id() == "test-cid-roundtrip"
        finally:
            reset_correlation_id(token)

    @pytest.mark.unit
    def test_reexports_are_same_objects_as_telemetry_logging(self) -> None:
        # Confirms the canonical aliasing -- there is exactly one
        # contextvar, not two (which would create silent fleet drift).
        from gubbi_common.telemetry.logging import (
            get_correlation_id as tel_get,
        )
        from gubbi_common.telemetry.logging import (
            reset_correlation_id as tel_reset,
        )
        from gubbi_common.telemetry.logging import (
            set_correlation_id as tel_set,
        )

        assert set_correlation_id is tel_set
        assert get_correlation_id is tel_get
        assert reset_correlation_id is tel_reset
