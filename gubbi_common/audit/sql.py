"""SQL templates for writing into the journalctl ``audit_log`` table.

This module exposes:

* ``AUDIT_INSERT_SQL`` -- the canonical 9-column insert (used by
  journalctl's ``record_audit`` helper).
* ``AUDIT_INSERT_SQL_RICH`` -- 7-column insert that explicitly sets
  ``occurred_at`` (used by cloud-api when the wire timestamp differs from
  ``now()``).
* ``AUDIT_INSERT_DEDUPED_SQL`` -- 6-column insert with ON CONFLICT DO
  NOTHING for re-delivery dedup. Relies on the partial unique index
  ``audit_log_content_hash_uidx`` (journalctl migration 0016).
* ``AUDIT_INSERT_SHORT_SQL`` -- 6-column insert without ``occurred_at``
  or dedup; used by the legacy ``_record_kratos_audit`` path.
* ``record_audit_async`` -- typed wrapper around ``AUDIT_INSERT_SQL`` for
  callers that prefer a function over raw SQL (used by journalctl).
* ``VALID_ACTOR_TYPES`` -- the four values the CHECK constraint on
  ``audit_log.actor_type`` accepts.

Schema ownership lives in journalctl's Alembic chain. Any change to
column names or NOT NULL constraints must update the SQL constants here
and bump this package's major version.
"""

from __future__ import annotations

import ipaddress
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncpg

__all__ = [
    "AUDIT_INSERT_DEDUPED_SQL",
    "AUDIT_INSERT_SHORT_SQL",
    "AUDIT_INSERT_SQL",
    "AUDIT_INSERT_SQL_RICH",
    "VALID_ACTOR_TYPES",
    "record_audit_async",
]


# Values the audit_log.actor_type CHECK constraint accepts. Must stay in
# sync with journalctl's migration 0012 CHECK definition.
VALID_ACTOR_TYPES: frozenset[str] = frozenset(
    {
        "user",
        "admin",
        "system",
        "hydra_subject",
    }
)


# Canonical 9-column insert. Used by journalctl's ``record_audit``.
AUDIT_INSERT_SQL: str = """
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_type, target_id,
         reason, metadata, ip_address, user_agent)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::inet, $9)
"""


# 6-column insert without ``occurred_at`` or dedup. Used by the legacy
# ``_record_kratos_audit`` path (identity.updated / identity.deleted).
AUDIT_INSERT_SHORT_SQL: str = """
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_type, target_id, metadata)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb)
"""


# Atomic dedup for ``identity.updated`` re-deliveries. The partial unique
# index ``audit_log_content_hash_uidx`` (journalctl migration 0016) on
# ``(target_id, action, metadata->>'content_hash') WHERE metadata ?
# 'content_hash'`` enforces the constraint at the DB layer; this INSERT
# returns no rows on conflict, signaling the caller that the audit row
# was already written.
AUDIT_INSERT_DEDUPED_SQL: str = """
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_type, target_id, metadata)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb)
    ON CONFLICT (target_id, action, (metadata->>'content_hash'))
        WHERE metadata ? 'content_hash'
    DO NOTHING
    RETURNING 1
"""


# Richer audit insert -- includes occurred_at for events that need to
# record the wire timestamp distinct from server now().
AUDIT_INSERT_SQL_RICH: str = """
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_type, target_id, occurred_at, metadata)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
"""


async def record_audit_async(
    conn: asyncpg.Connection,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    reason: str | None = None,
    metadata: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Insert one immutable row into ``audit_log``.

    Caller owns transaction lifecycle. Executes a single INSERT inside
    whatever transaction (or autocommit context) the caller has open.

    Parameters
    ----------
    conn:
        Active ``asyncpg`` connection.
    actor_type:
        One of ``user``, ``admin``, ``system``, ``hydra_subject``.
        Raises ``ValueError`` on any other value.
    actor_id:
        Opaque actor identifier (UUID string,
        ``system:<worker-name>``, ``script:<name>``, ...).
    action:
        Event string. Use values from ``gubbi_common.audit.actions.Action``.
    target_type:
        Optional entity kind (``user``, ``tenant``, ``subscription``,
        ``secret``, ...).
    target_id:
        Optional entity identifier.
    reason:
        Optional human-readable explanation.
    metadata:
        Optional JSON-serialisable dict. Defaults to empty dict. Never
        include secret values or PII; pass hashes when forensics need
        the link.
    ip_address:
        Optional originating IP. Validated against ``ipaddress`` and
        cast to ``inet`` server-side.
    user_agent:
        Optional HTTP User-Agent string.

    Raises
    ------
    ValueError
        If ``actor_type`` is not one of the four accepted values, or if
        ``ip_address`` is not a valid IPv4 / IPv6 address.
    """
    if actor_type not in VALID_ACTOR_TYPES:
        raise ValueError(
            f"Invalid actor_type {actor_type!r}. " f"Must be one of: {sorted(VALID_ACTOR_TYPES)}"
        )

    # Validate AND normalize the IP. Three rules collapse near-duplicate
    # representations so audit forensics dedupe correctly:
    #   1. IPv4-mapped IPv6 ("::ffff:127.0.0.1") -> bare IPv4 ("127.0.0.1")
    #   2. IPv6 zero-compression ("2001:0db8:0:0:0:0:0:1" -> "2001:db8::1")
    #   3. Scoped IPv6 ("fe80::1%eth0") rejected -- zone IDs identify the
    #      originator's local interface, not a cross-machine address, and
    #      can carry control chars that poison log pipelines.
    normalized_ip: str | None = None
    if ip_address:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise ValueError(
                f"record_audit_async: invalid ip_address {ip_address!r}; "
                "must be a valid IPv4 or IPv6 address"
            ) from exc
        if isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj.scope_id is not None:
                raise ValueError(
                    f"record_audit_async: scoped IPv6 ip_address {ip_address!r} "
                    "rejected -- zone IDs are originator-local and not stored"
                )
            if ip_obj.ipv4_mapped is not None:
                ip_obj = ip_obj.ipv4_mapped
        normalized_ip = str(ip_obj)

    resolved_metadata: dict[str, Any] = metadata if metadata is not None else {}
    metadata_json = json.dumps(resolved_metadata)

    await conn.execute(
        AUDIT_INSERT_SQL,
        actor_type,
        actor_id,
        action,
        target_type,
        target_id,
        reason,
        metadata_json,
        normalized_ip,
        user_agent,
    )
