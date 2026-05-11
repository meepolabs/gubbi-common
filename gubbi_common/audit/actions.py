"""Canonical ``Action`` constants for the cross-repo ``audit_log`` table.

The ``audit_log`` table is owned by gubbi. Both gubbi and
gubbi-cloud write rows into it. Before this module existed, the
``Action`` enum was duplicated in each repo with no drift guard
(M3-review finding 3.3, CRITICAL): a rename in gubbi would let
cloud-api keep writing the old string and silently break downstream
queries.

This module is the single source of truth. Import ``Action`` from here
and use the class attributes; do not invent ad-hoc strings.

The string values use namespaced dot-separated identifiers
(``identity.created``, ``tenant.provisioned``) so downstream queries can
filter by prefix (``action LIKE 'identity.%'``).

Action is a ``StrEnum`` with an explicit ``__str__`` override. Without
the override, Python 3.11 returns ``"Action.LOGIN_FAILED"`` from
``str(Action.LOGIN_FAILED)`` while 3.12 returns ``"login_failed"`` -- a
silent format-string regression on minor-version upgrade. Pinning
``__str__`` to ``self.value`` keeps ``f"{Action.X}"`` and ``str(...)``
behaviour identical across both versions.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Action"]


class Action(StrEnum):
    """Audit-log action string constants.

    Values are persisted to ``audit_log.action`` (TEXT). Treat them as a
    contract: renaming a value is a breaking change for both repos and
    the downstream analytics that filter on it.
    """

    # ---------------------------------------------------------------
    # Identity lifecycle
    # ---------------------------------------------------------------
    # Namespaced ``identity.*`` so downstream queries can filter every
    # identity-shaped event with ``action LIKE 'identity.%'``. gubbi
    # Alembic migration 0015 rewrites legacy ``user.*`` rows from M2 to
    # the ``identity.*`` namespace.
    IDENTITY_CREATED = "identity.created"
    IDENTITY_UPDATED = "identity.updated"
    IDENTITY_DELETED = "identity.deleted"
    IDENTITY_RESTORED = "identity.restored"

    # ---------------------------------------------------------------
    # Tenant lifecycle
    # ---------------------------------------------------------------
    TENANT_PROVISIONED = "tenant.provisioned"
    TENANT_SUSPENDED = "tenant.suspended"
    TENANT_REACTIVATED = "tenant.reactivated"
    TENANT_DEPROVISIONED = "tenant.deprovisioned"
    # Emitted when a tenant row is orphaned (user_id set to NULL via
    # ON DELETE SET NULL on the tenants.user_id FK). See cloud-api
    # migration 0008 (m-real-bugs-cloud / M-3.2).
    TENANT_ORPHANED = "tenant.orphaned"

    # ---------------------------------------------------------------
    # Auth events
    # ---------------------------------------------------------------
    LOGIN_FAILED = "login_failed"

    # ---------------------------------------------------------------
    # Subscription lifecycle (M4+)
    # ---------------------------------------------------------------
    SUBSCRIPTION_CREATED = "subscription.created"
    SUBSCRIPTION_UPDATED = "subscription.updated"
    SUBSCRIPTION_CANCELED = "subscription.canceled"
    SUBSCRIPTION_OVERRIDE = "subscription.override"

    # ---------------------------------------------------------------
    # Billing gates
    # ---------------------------------------------------------------
    # Emitted when a billing operation (checkout, portal link) is
    # blocked because the user's email is not yet verified. See H-13
    # backlog: cloud-api previously used the raw literal string
    # "billing.email_unverified_blocked" pending this enum entry.
    BILLING_EMAIL_UNVERIFIED_BLOCKED = "billing.email_unverified_blocked"

    # ---------------------------------------------------------------
    # Journal content operations
    # ---------------------------------------------------------------
    ENTRY_CREATED = "entry.created"
    ENTRY_UPDATED = "entry.updated"
    ENTRY_DELETED = "entry.deleted"
    TOPIC_CREATED = "topic.created"
    CONVERSATION_SAVED = "conversation.saved"
    # Emitted by the extraction worker when a conversation finishes
    # processing (entries created, tags applied, processed_at stamped).
    CONVERSATION_EXTRACTED = "conversation.extracted"
    EXTRACTION_JOB_CREATED = "extraction_job.created"
    EXTRACTION_JOB_COMPLETED = "extraction_job.completed"
    EXTRACTION_JOB_FAILED = "extraction_job.failed"

    # ---------------------------------------------------------------
    # Privileged operations
    # ---------------------------------------------------------------
    SECRET_ROTATED = "secret.rotated"  # noqa: S105 -- action label, not a password
    ADMIN_QUERY_EXECUTED = "admin.query_executed"
    ENCRYPTION_KEY_ROTATED = "encryption.key_rotated"

    # ---------------------------------------------------------------
    # Admin / cleanup operations
    # ---------------------------------------------------------------
    USER_DELETED = "user.deleted"
    CLIENT_DELETED = "client.deleted"

    def __str__(self) -> str:
        # Lock 3.11 / 3.12 parity: without this override, 3.11's StrEnum
        # __str__ returns "Action.LOGIN_FAILED" while 3.12's returns
        # "login_failed". Pinning to self.value makes f-strings, logging,
        # and SQL parameter formatting identical across both versions.
        return self.value


# Consumer reference registries, updated from the actual consumer repos.
# Each list mixes TWO categories per consumer, distinguished by inline
# section comments:
#   1. "Currently wired" -- Action string values referenced in that repo's
#      production + test source today. Each entry cites its source file.
#   2. "Not yet wired" -- consumer-domain values defined here ahead of
#      their wiring (planned / in-flight per ongoing tasks). Each entry
#      cites the planned-or-in-flight surface; promote the comment to
#      "wired in <file>" when the entry lands.
# Both categories count as "registered to a consumer" for the drift-guard
# test `test_all_action_values_referenced_by_consumers` in
# tests/audit/test_actions.py, which asserts every Action constant appears
# in at least one registry. This guards both wire-format drift (consumer
# adds a raw string forgetting to register it) and dead-Action drift
# (constant defined in Action with no consumer claiming it).
_CLOUD_REFERENCED: frozenset[str] = frozenset(
    {
        # --- Currently wired in cloud-api production + test code ---
        "billing.email_unverified_blocked",  # gubbi-cloud/routers/billing.py
        "client.deleted",  # gubbi-cloud/admin/test_cleanup.py
        "identity.deleted",  # gubbi-cloud/webhooks/kratos.py
        "identity.updated",  # gubbi-cloud/webhooks/kratos.py
        "login_failed",  # gubbi-cloud/webhooks/kratos.py
        "subscription.canceled",  # gubbi-cloud/webhooks/stripe.py
        "subscription.created",  # gubbi-cloud/webhooks/stripe.py
        "subscription.updated",  # gubbi-cloud/webhooks/stripe.py
        "tenant.provisioned",  # gubbi-cloud/webhooks/kratos.py
        "user.deleted",  # gubbi-cloud/admin/test_cleanup.py
        # --- Cloud-side actions defined here, not yet wired in cloud code ---
        # Drift-guard accepts these as cloud-domain values whose wiring is in
        # flight or planned. Promote a comment to "wired in <file>" when each
        # lands; demote / remove if a planned action is dropped.
        "admin.query_executed",  # planned cloud admin endpoint
        "identity.restored",  # planned cloud kratos webhook (un-soft-delete)
        "secret.rotated",  # planned cloud secret-rotation surface
        "subscription.override",  # cloud-side deprecated alias for subscription.updated
        "tenant.deprovisioned",  # in flight via tenant-audit task (kratos.py)
        "tenant.orphaned",  # in flight via tenant-audit task (kratos.py)
        "tenant.reactivated",  # planned cloud tenant lifecycle
        "tenant.suspended",  # planned cloud tenant lifecycle
    }
)

_GUBBI_REFERENCED: frozenset[str] = frozenset(
    {
        # --- Currently wired in gubbi code ---
        "conversation.saved",  # gubbi/core/audit_decorator.py (ACTION_CONVERSATION_SAVED)
        "conversation.extracted",  # gubbi/extraction/jobs/extract_conversation.py
        "extraction_job.created",  # gubbi/gubbi/api/v1/ingest.py
        "extraction_job.completed",  # gubbi/gubbi/extraction/jobs/extract_conversation.py
        "extraction_job.failed",  # gubbi/gubbi/extraction/jobs/extract_conversation.py
        "entry.created",  # gubbi/core/audit_decorator.py (ACTION_ENTRY_CREATED)
        "entry.deleted",  # gubbi/core/audit_decorator.py (ACTION_ENTRY_DELETED)
        "entry.updated",  # gubbi/core/audit_decorator.py (ACTION_ENTRY_UPDATED)
        "encryption.key_rotated",  # gubbi/scripts/rotate_encryption_key.py
        "identity.created",  # gubbi/users/bootstrap.py
        "identity.deleted",  # gubbi/audit.py
        "topic.created",  # gubbi/core/audit_decorator.py (ACTION_TOPIC_CREATED)
    }
)
