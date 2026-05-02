"""Tests for the canonical ``Action`` enum.

These tests verify Action's invariants (string-typed values, stable repr, no
duplicates). Drift detection between gubbi-common and its consumers lives
*in the consumer repos* as AST scans of their own source -- gubbi-common
cannot statically know which constants its consumers import.
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
def test_journal_content_values_present() -> None:
    assert Action.ENTRY_CREATED == "entry.created"
    assert Action.ENTRY_UPDATED == "entry.updated"
    assert Action.ENTRY_DELETED == "entry.deleted"
    assert Action.TOPIC_CREATED == "topic.created"
    assert Action.CONVERSATION_SAVED == "conversation.saved"


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
