"""Tests for the canonical ``TargetKind`` enum.

Verifies TargetKind's invariants (string-typed values, stable repr, no
duplicates) plus a registry-level drift guard:
``test_all_target_kind_values_referenced_by_consumers`` asserts every
TargetKind constant is claimed by at least one consumer registry
(``_GUBBI_TARGET_KINDS`` or ``_CLOUD_TARGET_KINDS`` in
``gubbi_common.audit.targets``). The registries are hand-maintained from
consumer source at release time; the test catches both dead kinds in
the enum and missing claims when a consumer adds a new audit call.

Consumer repos additionally run AST scans against their own source to
verify every raw-string target_kind value at a call site maps to a
TargetKind constant. The two sides are complementary: registries here
guard the canonical enum; AST scans there guard call-site usage.
"""

from __future__ import annotations

import pytest

from gubbi_common.audit.targets import TargetKind


@pytest.mark.unit
def test_journal_content_kinds_present() -> None:
    assert TargetKind.TOPIC == "topic"
    assert TargetKind.ENTRY == "entry"
    assert TargetKind.CONVERSATION == "conversation"
    assert TargetKind.EXTRACTION_JOB == "extraction_job"


@pytest.mark.unit
def test_identity_billing_kinds_present() -> None:
    assert TargetKind.USER == "user"
    assert TargetKind.TENANT == "tenant"
    assert TargetKind.SUBSCRIPTION == "subscription"
    assert TargetKind.OAUTH_CLIENT == "oauth_client"


@pytest.mark.unit
def test_target_kind_values_are_strings() -> None:
    """TargetKind values are plain strings (asyncpg-friendly)."""
    assert isinstance(TargetKind.ENTRY, str)
    # Stable string-equality with raw literals: no Enum wrapping.
    assert TargetKind.ENTRY == "entry"


@pytest.mark.unit
def test_target_kind_repr_is_stable_string() -> None:
    """TargetKind constants are interchangeable with their string values."""
    assert f"{TargetKind.USER}" == "user"
    assert str(TargetKind.SUBSCRIPTION) == "subscription"


@pytest.mark.unit
def test_no_duplicate_target_kind_values() -> None:
    """Each TargetKind.X must map to a unique string value."""
    values = [member.value for member in TargetKind]
    assert len(values) == len(set(values)), f"duplicate TargetKind values: {values}"


@pytest.mark.unit
def test_all_target_kind_values_referenced_by_consumers() -> None:
    """Every TargetKind value must appear in at least one consumer registry.

    This is a drift guard: if a contributor renames or removes a
    TargetKind constant, or if a consumer drops its reference to a
    value, this test fires until the registries are updated to reflect
    reality.
    """
    from gubbi_common.audit.targets import (
        _CLOUD_TARGET_KINDS,
        _GUBBI_TARGET_KINDS,
        TargetKind,
    )

    referenced = _CLOUD_TARGET_KINDS | _GUBBI_TARGET_KINDS
    missing: list[str] = []
    for member in TargetKind:
        assert isinstance(
            member.value, str
        ), f"TargetKind.{member.name} must be a string, got {type(member.value).__name__}"
        if member not in referenced:
            missing.append(f"{member.name}={member.value!r}")

    assert not missing, (
        "The following TargetKind constants are not found in any consumer registry. "
        "Add them to _GUBBI_TARGET_KINDS or _CLOUD_TARGET_KINDS if they are currently "
        "used, or remove them from TargetKind if they are dead:\n"
        + "\n".join(f"  - {m}" for m in missing)
    )


# ===========================================================================
# StrEnum invariants with explicit __str__ override (3.11/3.12 parity)
# ===========================================================================


@pytest.mark.unit
def test_target_kind_is_str_enum() -> None:
    from enum import StrEnum

    assert issubclass(TargetKind, StrEnum)


@pytest.mark.unit
def test_target_kind_str_returns_value() -> None:
    """``str(TargetKind.X)`` must return the bare value on both 3.11 and 3.12.

    Without an explicit ``__str__`` override, Python 3.11 returns
    ``"TargetKind.ENTRY"`` and 3.12 returns ``"entry"`` -- a silent
    format-string regression on upgrade. The override locks behaviour.
    """
    assert str(TargetKind.ENTRY) == "entry"
    assert str(TargetKind.USER) == "user"


@pytest.mark.unit
def test_target_kind_fstring_returns_value() -> None:
    assert f"{TargetKind.TOPIC}" == "topic"
    assert f"{TargetKind.SUBSCRIPTION}" == "subscription"


@pytest.mark.unit
def test_target_kind_equality_with_raw_string_holds() -> None:
    """StrEnum members compare equal to their raw string values."""
    assert TargetKind.ENTRY == "entry"
    assert TargetKind.USER == "user"
