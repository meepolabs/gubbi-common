"""Canonical ``Action`` constants for the cross-repo ``audit_log`` table.

The ``audit_log`` table is owned by journalctl. Both journalctl and
journalctl-cloud write rows into it. Before this module existed, the
``Action`` enum was duplicated in each repo with no drift guard
(M3-review finding 3.3, CRITICAL): a rename in journalctl would let
cloud-api keep writing the old string and silently break downstream
queries.

This module is the single source of truth. Import ``Action`` from here
and use the class attributes; do not invent ad-hoc strings.

The string values use namespaced dot-separated identifiers
(``identity.created``, ``tenant.provisioned``) so downstream queries can
filter by prefix (``action LIKE 'identity.%'``).
"""

from __future__ import annotations

from typing import Final

__all__ = ["Action"]


class Action:
    """Audit-log action string constants.

    Values are persisted to ``audit_log.action`` (TEXT). Treat them as a
    contract: renaming a value is a breaking change for both repos and
    the downstream analytics that filter on it.
    """

    # ---------------------------------------------------------------
    # Identity lifecycle
    # ---------------------------------------------------------------
    # Namespaced ``identity.*`` so downstream queries can filter every
    # identity-shaped event with ``action LIKE 'identity.%'``. journalctl
    # Alembic migration 0015 rewrites legacy ``user.*`` rows from M2 to
    # the ``identity.*`` namespace.
    IDENTITY_CREATED: Final = "identity.created"
    IDENTITY_UPDATED: Final = "identity.updated"
    IDENTITY_DELETED: Final = "identity.deleted"
    IDENTITY_RESTORED: Final = "identity.restored"

    # ---------------------------------------------------------------
    # Tenant lifecycle
    # ---------------------------------------------------------------
    TENANT_PROVISIONED: Final = "tenant.provisioned"
    TENANT_SUSPENDED: Final = "tenant.suspended"
    TENANT_REACTIVATED: Final = "tenant.reactivated"
    TENANT_DEPROVISIONED: Final = "tenant.deprovisioned"
    # Emitted when a tenant row is orphaned (user_id set to NULL via
    # ON DELETE SET NULL on the tenants.user_id FK). See cloud-api
    # migration 0008 (m-real-bugs-cloud / M-3.2).
    TENANT_ORPHANED: Final = "tenant.orphaned"

    # ---------------------------------------------------------------
    # Auth events
    # ---------------------------------------------------------------
    LOGIN_FAILED: Final = "login_failed"

    # ---------------------------------------------------------------
    # Subscription lifecycle (M4+)
    # ---------------------------------------------------------------
    SUBSCRIPTION_CREATED: Final = "subscription.created"
    SUBSCRIPTION_UPDATED: Final = "subscription.updated"
    SUBSCRIPTION_CANCELED: Final = "subscription.canceled"
    SUBSCRIPTION_OVERRIDE: Final = "subscription.override"

    # ---------------------------------------------------------------
    # Billing gates
    # ---------------------------------------------------------------
    # Emitted when a billing operation (checkout, portal link) is
    # blocked because the user's email is not yet verified. See H-13
    # backlog: cloud-api previously used the raw literal string
    # "billing.email_unverified_blocked" pending this enum entry.
    BILLING_EMAIL_UNVERIFIED_BLOCKED: Final = "billing.email_unverified_blocked"

    # ---------------------------------------------------------------
    # Journal content operations
    # ---------------------------------------------------------------
    ENTRY_CREATED: Final = "entry.created"
    ENTRY_UPDATED: Final = "entry.updated"
    ENTRY_DELETED: Final = "entry.deleted"
    TOPIC_CREATED: Final = "topic.created"
    CONVERSATION_SAVED: Final = "conversation.saved"

    # ---------------------------------------------------------------
    # Privileged operations
    # ---------------------------------------------------------------
    SECRET_ROTATED: Final = "secret.rotated"  # noqa: S105 -- action label, not a password
    ADMIN_QUERY_EXECUTED: Final = "admin.query_executed"
    ENCRYPTION_KEY_ROTATED: Final = "encryption.key_rotated"

    # ---------------------------------------------------------------
    # Admin / cleanup operations
    # ---------------------------------------------------------------
    USER_DELETED: Final = "user.deleted"
    CLIENT_DELETED: Final = "client.deleted"
