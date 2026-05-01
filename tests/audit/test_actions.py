"""Tests for the canonical ``Action`` enum."""

from __future__ import annotations

import pytest

from gubbi_common.audit.actions import Action

# Values the journalctl and journalctl-cloud repos reference today. Adding a
# value here without adding it to ``Action`` is a contract break.
_CLOUD_REFERENCED: frozenset[str] = frozenset(
    {
        "identity.created",
        "identity.updated",
        "identity.deleted",
        "tenant.provisioned",
        "login_failed",
    }
)

_JOURNALCTL_REFERENCED: frozenset[str] = frozenset(
    {
        "identity.created",
        "identity.deleted",
        "encryption.key_rotated",
    }
)


@pytest.mark.unit
def test_identity_lifecycle_values_present() -> None:
    # Arrange / Act / Assert
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
    assert Action.SUBSCRIPTION_CANCELED == "subscription.canceled"
    assert Action.SUBSCRIPTION_OVERRIDE == "subscription.override"


@pytest.mark.unit
def test_privileged_op_values_present() -> None:
    assert Action.SECRET_ROTATED == "secret.rotated"
    assert Action.ADMIN_QUERY_EXECUTED == "admin.query_executed"
    assert Action.ENCRYPTION_KEY_ROTATED == "encryption.key_rotated"


@pytest.mark.unit
def test_cloud_referenced_values_are_all_present() -> None:
    """Every Action.X used in journalctl-cloud must exist in the shared enum."""
    # Arrange
    shared_values = {
        getattr(Action, name)
        for name in dir(Action)
        if not name.startswith("_") and isinstance(getattr(Action, name), str)
    }

    # Act / Assert
    missing = _CLOUD_REFERENCED - shared_values
    assert not missing, f"cloud-api references missing from Action: {missing}"


@pytest.mark.unit
def test_journalctl_referenced_values_are_all_present() -> None:
    """Every Action.X used in journalctl must exist in the shared enum."""
    # Arrange
    shared_values = {
        getattr(Action, name)
        for name in dir(Action)
        if not name.startswith("_") and isinstance(getattr(Action, name), str)
    }

    # Act / Assert
    missing = _JOURNALCTL_REFERENCED - shared_values
    assert not missing, f"journalctl references missing from Action: {missing}"


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
