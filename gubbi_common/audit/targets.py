"""Canonical ``TargetKind`` constants for the cross-repo ``audit_log`` table.

The ``audit_log.target_kind`` column was added in gubbi migration 0020 as
a namespace discriminator for the partial unique index
``audit_log_content_hash_uidx``. Before this column existed, the dedup
index keyed on ``(target_id, action, metadata->>'content_hash')`` could
false-positive across kinds whose ``target_id`` shapes overlap (e.g.
entry id ``"42"`` colliding with a topic path ``"42"``). ``target_kind``
discriminates the namespace so the dedup contract is unambiguous.

This module is the single source of truth for the legal kind values.
Import ``TargetKind`` here and use the class attributes; do not invent
ad-hoc strings on consumer call sites.

``TargetKind`` is a ``StrEnum`` with an explicit ``__str__`` override.
Without the override, Python 3.11 returns ``"TargetKind.ENTRY"`` from
``str(TargetKind.ENTRY)`` while 3.12 returns ``"entry"`` -- a silent
format-string regression on minor-version upgrade. Pinning ``__str__``
to ``self.value`` keeps ``f"{TargetKind.X}"`` and ``str(...)``
behaviour identical across both versions.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

__all__ = ["TargetKind"]


class TargetKind(StrEnum):
    """Audit-log target_kind string constants.

    Values are persisted to ``audit_log.target_kind`` (TEXT). Treat them
    as a contract: renaming a value is a breaking change for both repos
    and the partial unique index ``audit_log_content_hash_uidx`` that
    keys on the column.
    """

    # ---------------------------------------------------------------
    # Journal content kinds (wired in gubbi)
    # ---------------------------------------------------------------
    TOPIC = "topic"
    ENTRY = "entry"
    CONVERSATION = "conversation"
    EXTRACTION_JOB = "extraction_job"

    # ---------------------------------------------------------------
    # Identity / billing kinds (wired in gubbi + gubbi-cloud)
    # ---------------------------------------------------------------
    USER = "user"
    TENANT = "tenant"
    SUBSCRIPTION = "subscription"
    OAUTH_CLIENT = "oauth_client"

    def __str__(self) -> str:
        # Lock 3.11 / 3.12 parity: without this override, 3.11's StrEnum
        # __str__ returns "TargetKind.ENTRY" while 3.12's returns
        # "entry". Pinning to self.value makes f-strings, logging, and
        # SQL parameter formatting identical across both versions.
        return self.value


# Consumer reference registries, updated from the actual consumer repos.
# Each frozenset mixes TWO categories per consumer, distinguished by
# inline section comments:
#   1. "Currently wired" -- TargetKind string values referenced in that
#      repo's production + test source today. Each entry cites its
#      source file.
#   2. "Not yet wired" -- consumer-domain values defined here ahead of
#      their wiring (planned / in-flight per ongoing tasks). Each entry
#      cites the planned-or-in-flight surface; promote the comment to
#      "wired in <file>" when the entry lands.
# Both categories count as "registered to a consumer" for the
# drift-guard test ``test_all_target_kind_values_referenced_by_consumers``
# in tests/audit/test_targets.py, which asserts every TargetKind
# constant appears in at least one registry. This guards both
# wire-format drift (consumer adds a raw string forgetting to register
# it) and dead-TargetKind drift (constant defined here with no consumer
# claiming it).
_GUBBI_TARGET_KINDS: Final[frozenset[TargetKind]] = frozenset(
    {
        # --- Currently wired in gubbi code ---
        TargetKind.TOPIC,  # gubbi/gubbi/tools/topics.py
        TargetKind.ENTRY,  # gubbi/gubbi/tools/entries.py
        TargetKind.CONVERSATION,  # gubbi/gubbi/tools/conversations.py
        TargetKind.EXTRACTION_JOB,  # gubbi/gubbi/extraction/jobs/extract_conversation.py
        TargetKind.USER,  # planned gubbi user-lifecycle audit surface
    }
)

_CLOUD_TARGET_KINDS: Final[frozenset[TargetKind]] = frozenset(
    {
        # --- Currently wired in cloud-api production + test code ---
        TargetKind.SUBSCRIPTION,  # gubbi-cloud/gubbi_cloud/webhooks/stripe/_helpers.py
        TargetKind.USER,  # gubbi-cloud/gubbi_cloud/webhooks/kratos/handlers/identity_updated.py
        TargetKind.TENANT,  # gubbi-cloud/gubbi_cloud/services/admin/llm_budget.py
        TargetKind.OAUTH_CLIENT,  # gubbi-cloud/gubbi_cloud/admin/test_cleanup.py
    }
)
