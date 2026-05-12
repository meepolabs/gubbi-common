"""SQL templates for writing into the gubbi ``audit_log`` table.

This module exposes:

* ``AUDIT_INSERT_SQL`` -- the canonical 9-column insert (used by
  gubbi's ``record_audit`` helper).
* ``AUDIT_INSERT_SQL_RICH`` -- 7-column insert that explicitly sets
  ``occurred_at`` (used by cloud-api when the wire timestamp differs from
  ``now()``).
* ``AUDIT_INSERT_DEDUPED_SQL`` -- 7-column insert
  ``(actor_type, actor_id, action, target_kind, target_type, target_id,
  metadata)`` with ON CONFLICT DO NOTHING for re-delivery dedup. Relies
  on the partial unique index ``audit_log_content_hash_uidx`` (gubbi
  migration 0020) keyed on
  ``(target_kind, target_id, action, (metadata->>'content_hash'))
  WHERE metadata ? 'content_hash'``.
* ``AUDIT_INSERT_SHORT_SQL`` -- 6-column insert without ``occurred_at``
  or dedup; used by the legacy ``_record_kratos_audit`` path.
* ``record_audit_async`` -- typed wrapper around ``AUDIT_INSERT_SQL`` for
  callers that prefer a function over raw SQL (used by gubbi).
* ``VALID_ACTOR_TYPES`` -- the four values the CHECK constraint on
  ``audit_log.actor_type`` accepts.

Schema ownership lives in gubbi's Alembic chain. Any change to
column names or NOT NULL constraints must update the SQL constants here
and bump this package's major version.

SQL string constants use textwrap.dedent() so the first line of the SQL
body has no leading whitespace -- this ensures stable fingerprints in
pg_stat_statements across all consumers.
"""

from __future__ import annotations

import ipaddress
import json
import textwrap
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from gubbi_common.audit.targets import TargetKind
from gubbi_common.telemetry.allowlist import is_banned_key

if TYPE_CHECKING:
    import asyncpg

__all__ = [
    "AUDIT_INSERT_DEDUPED_SQL",
    "AUDIT_INSERT_SHORT_SQL",
    "AUDIT_INSERT_SQL",
    "AUDIT_INSERT_SQL_RICH",
    "MAX_METADATA_BYTES",
    "VALID_ACTOR_TYPES",
    "record_audit_async",
]


# Hard cap on the JSON-encoded size of an audit row's ``metadata`` column.
# 4 KiB matches the rule of thumb for JSONB inline storage and ensures any
# single audit row stays well under TOAST overflow thresholds. Callers
# whose payload genuinely exceeds this limit must summarise (counts,
# hashes, IDs) rather than stuff full content into the column.
MAX_METADATA_BYTES: Final[int] = 4096

# Maximum recursion depth for metadata redaction (DoS guard). The mutual
# recursion between ``_redact_metadata`` and ``_redact_metadata_value``
# increments depth by 2 per dict-nesting level, so a value of 20
# corresponds to ~9-10 real dict-nesting levels. Any legitimate audit
# payload nests well under this; the cap exists to bound the worst case
# from a malicious or buggy caller. Exceeding the cap raises
# ``ValueError`` so the caller surfaces the invalid payload at the
# boundary instead of silently truncating or crashing the worker.
_MAX_REDACT_DEPTH: Final[int] = 20

# Sentinel placeholder substituted in for any banned-key value during
# metadata redaction. Mirrors the convention used elsewhere in the
# privacy-defense layer (telemetry allowlist).
_REDACTED: Final[str] = "[REDACTED]"

# Accepted non-UUID actor / target identifier prefixes. Rows must look
# like a UUID or carry one of these prefixes so downstream analytics can
# safely group on actor_id / target_id without joining a freeform string
# table.
_AUDIT_ID_PREFIXES: Final[tuple[str, ...]] = (
    "system:",
    "script:",
    "hydra_subject:",
)


# Values the audit_log.actor_type CHECK constraint accepts. Must stay in
# sync with gubbi's migration 0012 CHECK definition.
VALID_ACTOR_TYPES: frozenset[str] = frozenset(
    {
        "user",
        "admin",
        "system",
        "hydra_subject",
    }
)


# Canonical 9-column insert. Used by gubbi's ``record_audit``.
AUDIT_INSERT_SQL: str = textwrap.dedent(
    """\
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_type, target_id,
         reason, metadata, ip_address, user_agent)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::inet, $9)"""
)


# 6-column insert without ``occurred_at`` or dedup. Used by the legacy
# ``_record_kratos_audit`` path (identity.updated / identity.deleted).
AUDIT_INSERT_SHORT_SQL: str = textwrap.dedent(
    """\
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_type, target_id, metadata)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb)"""
)


# Atomic dedup for ``identity.updated`` re-deliveries. The partial unique
# index ``audit_log_content_hash_uidx`` (gubbi migration 0020) on
# ``(target_kind, target_id, action, metadata->>'content_hash')
# WHERE metadata ? 'content_hash'`` enforces the constraint at the DB
# layer; this INSERT returns no rows on conflict, signaling the caller
# that the audit row was already written. ``target_kind`` was added in
# migration 0020 as a namespace discriminator so heterogeneous
# ``target_id`` values across kinds (e.g. entry id "42" vs. topic path
# "42") cannot trip a false unique-violation.
AUDIT_INSERT_DEDUPED_SQL: str = textwrap.dedent(
    """\
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_kind, target_type, target_id, metadata)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
    ON CONFLICT (target_kind, target_id, action, (metadata->>'content_hash'))
        WHERE metadata ? 'content_hash'
    DO NOTHING
    RETURNING 1"""
)


# Richer audit insert -- includes occurred_at for events that need to
# record the wire timestamp distinct from server now().
AUDIT_INSERT_SQL_RICH: str = textwrap.dedent(
    """\
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_type, target_id, occurred_at, metadata)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)"""
)


def _validate_audit_id(value: str | None, *, field: str) -> None:
    """Validate ``actor_id`` / ``target_id`` shape.

    Accepts either a UUID string (any valid format the standard library
    parses) or a string starting with one of ``_AUDIT_ID_PREFIXES``
    (``system:``, ``script:``, ``hydra_subject:``). ``None`` passes
    through silently for the optional ``target_id`` field. Empty /
    whitespace-only strings are rejected.

    The ``UUID(value)`` call raises ``ValueError`` for malformed input;
    ``AttributeError`` and ``TypeError`` are unreachable thanks to the
    None / empty-string guards above and the ``str | None`` annotation.
    Catching only ``ValueError`` here makes the surface the function
    actually defends against legible at the call site.
    """
    if value is None:
        return
    if not value or not value.strip():
        raise ValueError(
            f"record_audit_async: {field} must be a UUID or one of "
            f"{list(_AUDIT_ID_PREFIXES)}; got empty / whitespace value"
        )
    try:
        UUID(value)
        return
    except ValueError:
        pass
    if not any(value.startswith(prefix) for prefix in _AUDIT_ID_PREFIXES):
        raise ValueError(
            f"record_audit_async: {field}={value!r} is not a UUID and "
            f"does not start with one of {list(_AUDIT_ID_PREFIXES)}"
        )


def _redact_metadata_value(value: Any, depth: int = 0) -> Any:
    """Recursively walk *value*, redacting any banned-key entries inside dicts.

    Lists and tuples recurse element-wise -- tuples are emitted as lists
    because ``json.dumps`` would already collapse them to JSON arrays,
    and downstream consumers read the metadata as JSON. Scalars pass
    through. *depth* tracks recursion depth across the dict / list /
    tuple mutual-recursion edges so a pathological input cannot blow
    the stack; ``ValueError`` is raised once depth exceeds
    :data:`_MAX_REDACT_DEPTH`.
    """
    if depth > _MAX_REDACT_DEPTH:
        raise ValueError("metadata exceeds redaction depth limit")
    if isinstance(value, dict):
        return _redact_metadata(value, depth=depth + 1)
    if isinstance(value, list | tuple):
        return [_redact_metadata_value(v, depth=depth + 1) for v in value]
    return value


def _redact_metadata(meta: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Return a NEW dict with every banned-key value replaced by ``[REDACTED]``.

    Pure: input is not mutated. Recursion descends into nested dicts and
    lists; non-container values pass through unchanged. Banned keys are
    those flagged by ``gubbi_common.telemetry.is_banned_key`` -- the same
    classifier used by the OTel attribute allowlist, so the audit-row
    privacy rules and the telemetry rules cannot drift.

    *depth* tracks recursion depth; ``ValueError`` is raised once depth
    exceeds :data:`_MAX_REDACT_DEPTH`. Both helpers share the same depth
    counter so the cap holds across the dict/list mutual-recursion edge.
    """
    if depth > _MAX_REDACT_DEPTH:
        raise ValueError("metadata exceeds redaction depth limit")
    out: dict[str, Any] = {}
    for key, value in meta.items():
        if isinstance(key, str) and is_banned_key(key):
            out[key] = _REDACTED
            continue
        out[key] = _redact_metadata_value(value, depth=depth + 1)
    return out


async def record_audit_async(
    conn: asyncpg.Connection,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    target_kind: TargetKind | None = None,
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
    target_kind:
        Required when ``target_id`` is supplied. Namespace discriminator
        added in gubbi migration 0020 so the dedup partial unique index
        ``audit_log_content_hash_uidx`` (keyed on
        ``(target_kind, target_id, action, metadata->>'content_hash')``)
        cannot collide across kinds with overlapping ``target_id`` shapes
        (e.g. entry id "42" vs. topic path "42"). Passing ``target_id``
        without ``target_kind`` raises ``ValueError``.

        **NOTE:** This wrapper writes via ``AUDIT_INSERT_SQL`` (9-column),
        which does NOT include ``target_kind`` in the INSERT column list.
        The argument is accepted for call-site invariant enforcement only;
        the persisted ``target_kind`` will be ``NULL`` on the row. Callers
        that need ``target_kind`` actually persisted (e.g. for dedup
        across heterogeneous target_id shapes) must use
        ``AUDIT_INSERT_DEDUPED_SQL`` directly. A follow-up may unify these
        paths; for v0.9.1 they are intentionally separate.
    reason:
        Optional human-readable explanation.
    metadata:
        Optional JSON-serialisable dict. Defaults to empty dict. Banned
        keys (per ``gubbi_common.telemetry.is_banned_key``) are redacted
        recursively, replacing each banned-key value with
        ``"[REDACTED]"``. The post-redaction JSON-encoded payload must be
        <= ``MAX_METADATA_BYTES`` (4096); larger payloads raise
        ``ValueError``.
    ip_address:
        Optional originating IP. Validated against ``ipaddress`` and
        cast to ``inet`` server-side.
    user_agent:
        Optional HTTP User-Agent string.

    Raises
    ------
    ValueError
        If ``actor_type`` is not one of the four accepted values, if
        ``target_id`` is supplied without ``target_kind``, if
        ``ip_address`` is not a valid IPv4 / IPv6 address, or if the
        post-redaction metadata exceeds ``MAX_METADATA_BYTES``.
    """
    if actor_type not in VALID_ACTOR_TYPES:
        raise ValueError(
            f"Invalid actor_type {actor_type!r}. " f"Must be one of: {sorted(VALID_ACTOR_TYPES)}"
        )

    if target_id is not None and target_kind is None:
        raise ValueError("target_id requires target_kind when writing to a dedup-indexed audit row")

    _validate_audit_id(actor_id, field="actor_id")
    _validate_audit_id(target_id, field="target_id")

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
    redacted_metadata = _redact_metadata(resolved_metadata)
    metadata_json = json.dumps(redacted_metadata)
    metadata_bytes = metadata_json.encode("utf-8")
    if len(metadata_bytes) > MAX_METADATA_BYTES:
        raise ValueError(
            f"record_audit_async: metadata exceeds {MAX_METADATA_BYTES}-byte cap "
            f"(got {len(metadata_bytes)} bytes after redaction); "
            "summarise (counts, hashes, IDs) rather than embedding full payloads"
        )

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
