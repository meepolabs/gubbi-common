"""Tests for the canonical ``Action`` enum.

Verifies Action's invariants (string-typed values, stable repr, no
duplicates) plus a registry-level drift guard:
``test_all_action_values_referenced_by_consumers`` asserts every Action
constant is claimed by at least one consumer registry
(``_CLOUD_REFERENCED`` or ``_GUBBI_REFERENCED`` in
``gubbi_common.audit.actions``). The registries are hand-maintained from
consumer source at release time; the test catches both dead Actions in
the enum and missing claims when a consumer adds a new audit call.

Consumer repos additionally run AST scans against their own source to
verify every raw-string action value at a call site maps to an Action
constant. The two sides are complementary: registries here guard the
canonical enum; AST scans there guard call-site usage.
"""

from __future__ import annotations

import pytest

from gubbi_common.audit.actions import Action


@pytest.mark.unit
def test_identity_lifecycle_values_present() -> None:
    assert Action.IDENTITY_CREATED == "identity.created"
    assert Action.IDENTITY_UPDATED == "identity.updated"
    assert Action.IDENTITY_DELETED == "identity.deleted"
    assert Action.IDENTITY_RESTORED == "identity.restored"


@pytest.mark.unit
def test_tenant_lifecycle_values_present() -> None:
    assert Action.TENANT_PROVISIONED == "tenant.provisioned"
    assert Action.TENANT_SUSPENDED == "tenant.suspended"
    assert Action.TENANT_REACTIVATED == "tenant.reactivated"
    assert Action.TENANT_DEPROVISIONED == "tenant.deprovisioned"
    assert Action.TENANT_ORPHANED == "tenant.orphaned"


@pytest.mark.unit
def test_auth_event_values_present() -> None:
    assert Action.LOGIN_FAILED == "login_failed"


@pytest.mark.unit
def test_subscription_lifecycle_values_present() -> None:
    assert Action.SUBSCRIPTION_CREATED == "subscription.created"
    assert Action.SUBSCRIPTION_UPDATED == "subscription.updated"
    assert Action.SUBSCRIPTION_CANCELED == "subscription.canceled"
    assert Action.SUBSCRIPTION_OVERRIDE == "subscription.override"


@pytest.mark.unit
def test_billing_gate_values_present() -> None:
    assert Action.BILLING_EMAIL_UNVERIFIED_BLOCKED == "billing.email_unverified_blocked"


@pytest.mark.unit
def test_journal_content_values_present() -> None:
    assert Action.ENTRY_CREATED == "entry.created"
    assert Action.ENTRY_UPDATED == "entry.updated"
    assert Action.ENTRY_DELETED == "entry.deleted"
    assert Action.TOPIC_CREATED == "topic.created"
    assert Action.CONVERSATION_SAVED == "conversation.saved"
    assert Action.CONVERSATION_EXTRACTED == "conversation.extracted"


@pytest.mark.unit
def test_privileged_op_values_present() -> None:
    assert Action.SECRET_ROTATED == "secret.rotated"
    assert Action.ADMIN_QUERY_EXECUTED == "admin.query_executed"
    assert Action.ENCRYPTION_KEY_ROTATED == "encryption.key_rotated"


@pytest.mark.unit
def test_admin_cleanup_values_present() -> None:
    assert Action.USER_DELETED == "user.deleted"
    assert Action.CLIENT_DELETED == "client.deleted"


@pytest.mark.unit
def test_action_values_are_strings_not_enum_members() -> None:
    """Action values are plain strings (asyncpg-friendly, no .value attribute)."""
    assert isinstance(Action.IDENTITY_CREATED, str)
    # Stable string-equality with raw literals: no Enum wrapping.
    assert Action.IDENTITY_CREATED == "identity.created"


@pytest.mark.unit
def test_action_repr_is_stable_string() -> None:
    """Action constants are interchangeable with their string values."""
    assert f"{Action.LOGIN_FAILED}" == "login_failed"
    assert str(Action.TENANT_PROVISIONED) == "tenant.provisioned"


@pytest.mark.unit
def test_no_duplicate_action_values() -> None:
    """Each Action.X must map to a unique string value."""
    values = [
        getattr(Action, name)
        for name in dir(Action)
        if not name.startswith("_") and isinstance(getattr(Action, name), str)
    ]
    assert len(values) == len(set(values)), f"duplicate Action values: {values}"


@pytest.mark.unit
def test_all_action_values_referenced_by_consumers() -> None:
    """Every Action string value must appear in at least one consumer registry.

    This is a drift guard: if a contributor renames or removes an Action constant,
    or if a consumer drops its reference to a value, this test fires until the
    registries are updated to reflect reality.
    """
    from gubbi_common.audit.actions import (
        _CLOUD_REFERENCED,
        _GUBBI_REFERENCED,
        Action,
    )

    referenced = _CLOUD_REFERENCED | _GUBBI_REFERENCED
    missing: list[str] = []
    for attr_name in sorted(dir(Action)):
        if attr_name.startswith("_"):
            continue
        value = getattr(Action, attr_name)
        assert isinstance(
            value, str
        ), f"Action.{attr_name} must be a string, got {type(value).__name__}"
        if value not in referenced:
            missing.append(f"{attr_name}={value!r}")

    assert not missing, (
        "The following Action constants are not found in any consumer registry. "
        "Add them to _CLOUD_REFERENCED or _GUBBI_REFERENCED if they are currently used, "
        "or remove them from Action if they are dead:\n" + "\n".join(f"  - {m}" for m in missing)
    )
