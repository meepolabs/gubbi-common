"""SQL templates for writing into the gubbi ``audit_log`` table.

This module exposes two complementary INSERT shapes plus the typed
helpers that own them:

* ``AUDIT_INSERT_SQL`` -- the canonical 10-column insert
  ``(actor_type, actor_id, action, target_type, target_id, target_kind,
  reason, metadata, ip_address, user_agent)``. Use via
  :func:`record_audit_async`.
* ``AUDIT_INSERT_DEDUPED_SQL`` -- 7-column insert with ``ON CONFLICT
  DO NOTHING`` for re-delivery dedup, keyed on
  ``(actor_id, target_kind, target_id, action, metadata->>'content_hash')``
  (actor_id prepended in gubbi migration 0031 to close the cross-actor
  false-collision tampering vector; webhook idempotency preserved
  because each webhook source uses a constant actor_id).
  Use via :func:`record_audit_deduped_async`.
* ``record_audit_async`` -- canonical writer. Performs actor/target id
  validation, banned-key metadata redaction, IP normalization,
  metadata size enforcement, and emits an ``audit.write`` OTel span.
* ``record_audit_deduped_async`` -- dedup writer. Same validation
  surface as ``record_audit_async`` but routes through
  ``AUDIT_INSERT_DEDUPED_SQL`` so re-deliveries collapse at the
  partial unique index ``audit_log_content_hash_uidx``. Returns
  ``True`` when a row was inserted, ``False`` when ON CONFLICT
  skipped the write.
* ``VALID_ACTOR_TYPES`` -- the four values the CHECK constraint on
  ``audit_log.actor_type`` accepts.

Schema ownership lives in gubbi's Alembic chain. Any change to
column names or NOT NULL constraints must update the SQL constants
here and bump this package's major version.

SQL string constants use textwrap.dedent() so the first line of the
SQL body has no leading whitespace -- this ensures stable
fingerprints in pg_stat_statements across all consumers.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import textwrap
import time
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from gubbi_common.audit.targets import TargetKind
from gubbi_common.correlation import get_correlation_id
from gubbi_common.telemetry.allowlist import is_banned_key

if TYPE_CHECKING:
    import asyncpg

__all__ = [
    "AUDIT_INSERT_DEDUPED_SQL",
    "AUDIT_INSERT_SQL",
    "AUDIT_WRITE_SPAN_NAME",
    "MAX_METADATA_BYTES",
    "VALID_ACTOR_TYPES",
    "record_audit_async",
    "record_audit_deduped_async",
]

logger = logging.getLogger(__name__)


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

# Nanoseconds per millisecond -- used when computing OTel span latency.
_NS_PER_MS: Final[int] = 1_000_000

# Canonical span name emitted by both writers. Held here (rather than
# imported from a per-service module) so gubbi-cloud spans use the same
# name as gubbi spans without having to thread a constant through.
AUDIT_WRITE_SPAN_NAME: Final[str] = "audit.write"

# Tracer name used when emitting audit spans. The gubbi-side allowlist
# already keys on the span name (not the tracer name); cloud follows
# the same convention.
_TRACER_NAME: Final[str] = "gubbi_common.audit"


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


# Canonical 10-column insert. Includes ``target_kind`` (migration 0020)
# so a single canonical writer can satisfy every non-dedup audit path.
AUDIT_INSERT_SQL: str = textwrap.dedent(
    """\
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_type, target_id, target_kind,
         reason, metadata, ip_address, user_agent)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::inet, $10)"""
)


# Atomic dedup for re-deliveries. The partial unique index
# ``audit_log_content_hash_uidx`` (rebuilt by gubbi migration 0031) on
# ``(actor_id, target_kind, target_id, action, metadata->>'content_hash')
# WHERE metadata ? 'content_hash'`` enforces the constraint at the DB
# layer; this INSERT returns no rows on conflict, signaling the caller
# that the audit row was already written. ``target_kind`` was added in
# migration 0020 as a namespace discriminator so heterogeneous
# ``target_id`` values across kinds (e.g. entry id "42" vs. topic path
# "42") cannot trip a false unique-violation. ``actor_id`` was
# prepended in migration 0031 to close a cross-actor false-collision
# tampering vector: without it, two distinct actors writing the same
# (target_kind, target_id, action, content_hash) tuple would collapse
# to a single audit row and the second actor's audit trail would be
# silently suppressed. Webhook idempotency is preserved because the
# cloud-api webhook handlers use a constant actor_id per source
# (e.g. ``system:stripe_webhook``, ``system:kratos_webhook``), so
# re-deliveries from the same source still dedup as before.
AUDIT_INSERT_DEDUPED_SQL: str = textwrap.dedent(
    """\
    INSERT INTO audit_log
        (actor_type, actor_id, action, target_kind, target_type, target_id, metadata)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
    ON CONFLICT (actor_id, target_kind, target_id, action, (metadata->>'content_hash'))
        WHERE metadata ? 'content_hash'
    DO NOTHING
    RETURNING 1"""
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


def _normalize_ip(ip_address: str | None) -> str | None:
    """Validate and normalize an originating IP.

    Three rules collapse near-duplicate representations so audit
    forensics dedupe correctly:

    1. IPv4-mapped IPv6 ("::ffff:127.0.0.1") -> bare IPv4 ("127.0.0.1")
    2. IPv6 zero-compression ("2001:0db8:0:0:0:0:0:1" -> "2001:db8::1")
    3. Scoped IPv6 ("fe80::1%eth0") rejected -- zone IDs identify the
       originator's local interface, not a cross-machine address, and
       can carry control chars that poison log pipelines.

    Whitespace handling: trim first, then None-check. A whitespace-only
    string is truthy in Python -- without the strip, ``ipaddress.ip_address(" ")``
    would raise ``ValueError`` and surface as "invalid ip_address ' '" to
    the caller. Treating leading/trailing whitespace as "no address" is
    the more useful boundary behaviour for optional callers; pre-A3 code
    did this implicitly via an upstream ``.strip()``.
    """
    if ip_address is None:
        return None
    ip_address = ip_address.strip()
    if not ip_address:
        return None
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
    return str(ip_obj)


def _prepare_metadata(
    metadata: dict[str, Any] | None,
    *,
    correlation_id: str | None = None,
) -> str:
    """Redact, JSON-encode, and size-check an audit metadata dict.

    Raises ``ValueError`` if the post-redaction JSON encoding exceeds
    :data:`MAX_METADATA_BYTES` (4096 bytes). Defaults a ``None`` input
    to an empty dict so callers do not need a sentinel.

    When ``correlation_id`` is supplied and the caller's metadata does
    NOT already carry that key, it is injected before redaction so the
    persisted audit row carries the request correlation_id for
    DB-side forensic joins (``WHERE metadata->>'correlation_id' = ...``).
    Caller-supplied ``correlation_id`` values in the metadata dict win
    over the kwarg -- explicit beats implicit.
    """
    resolved: dict[str, Any] = dict(metadata) if metadata is not None else {}
    if correlation_id is not None and "correlation_id" not in resolved:
        resolved["correlation_id"] = correlation_id
    redacted = _redact_metadata(resolved)
    payload = json.dumps(redacted)
    if len(payload.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError(
            f"record_audit_async: metadata exceeds {MAX_METADATA_BYTES}-byte cap "
            f"(got {len(payload.encode('utf-8'))} bytes after redaction); "
            "summarise (counts, hashes, IDs) rather than embedding full payloads"
        )
    return payload


# Legal string values for ``target_kind`` -- precomputed from
# ``TargetKind`` so the validator below can accept either an enum member
# or a bare string equal to one of the enum's values. Computed at
# module-import time so the membership check is O(1) on every audit
# write. ``TargetKind`` is the single source of truth (see
# ``gubbi_common/audit/targets.py``); adding a kind there extends this
# set automatically.
_VALID_TARGET_KIND_STRINGS: frozenset[str] = frozenset(member.value for member in TargetKind)


def _validate_actor_and_target(
    *,
    actor_type: str,
    actor_id: str,
    target_id: str | None,
    target_kind: TargetKind | str | None,
) -> None:
    """Apply the actor/target validation rules shared by both writers.

    ``actor_id`` is shape-validated (UUID or one of the
    ``_AUDIT_ID_PREFIXES``) -- the S2 LOW-1 footgun fix.

    ``target_id`` is NOT shape-validated: callers persist a mix of
    domain-internal IDs (conversation integers, entry integers,
    extraction-job UUIDs) and external-system IDs (Stripe subscription
    IDs, SHA256 email hashes). Forcing a UUID-or-prefix shape would
    require renaming every external ID at write time, fracturing
    forensic queries. The invariant we DO enforce is ``target_id
    requires target_kind`` so the dedup partial unique index can
    discriminate kinds.

    ``target_kind`` is shape-validated when not None: either a
    ``TargetKind`` enum member, or a bare string equal to one of the
    enum's ``.value`` strings. Typo strings (``"usr"``) and empty
    strings would otherwise be persisted verbatim and silently corrupt
    dedup grouping (the partial unique index keys on ``target_kind``)
    plus forensic queries that filter by kind. Rejecting at the boundary
    keeps ``TargetKind`` as the single source of truth.
    """
    if actor_type not in VALID_ACTOR_TYPES:
        raise ValueError(
            f"Invalid actor_type {actor_type!r}. Must be one of: {sorted(VALID_ACTOR_TYPES)}"
        )

    if target_id is not None and target_kind is None:
        raise ValueError("target_id requires target_kind when writing to a dedup-indexed audit row")

    # Bare-string target_kind must equal one of the enum's string values.
    # Empty strings and typos are rejected here. The ``isinstance`` guard
    # short-circuits enum members so we never re-validate what the type
    # system already proved.
    if (
        target_kind is not None
        and not isinstance(target_kind, TargetKind)
        and target_kind not in _VALID_TARGET_KIND_STRINGS
    ):
        raise ValueError(
            f"Invalid target_kind {target_kind!r}. Must be a TargetKind "
            f"enum member or one of: {sorted(_VALID_TARGET_KIND_STRINGS)}"
        )

    _validate_audit_id(actor_id, field="actor_id")


async def record_audit_async(
    conn: asyncpg.Connection,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    target_kind: TargetKind | str | None = None,
    reason: str | None = None,
    metadata: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    correlation_id: str | None = None,
) -> None:
    """Insert one immutable row into ``audit_log``.

    Caller owns transaction lifecycle. Executes a single INSERT inside
    whatever transaction (or autocommit context) the caller has open.
    Emits an ``audit.write`` OTel span carrying ``event_type``,
    ``target_id``, ``actor_type``, ``success``, and ``latency_ms``
    attributes (per the gubbi span shape).

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
        ``(actor_id, target_kind, target_id, action,
        metadata->>'content_hash')`` after migration 0031) cannot collide
        across kinds with overlapping ``target_id`` shapes
        (e.g. entry id "42" vs. topic path "42"). Passing ``target_id``
        without ``target_kind`` raises ``ValueError``.
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
    _validate_actor_and_target(
        actor_type=actor_type,
        actor_id=actor_id,
        target_id=target_id,
        target_kind=target_kind,
    )

    normalized_ip = _normalize_ip(ip_address)
    # Default correlation_id from the request-scoped ContextVar so HTTP
    # call sites don't have to thread it manually; background tasks /
    # script entry points that have no inbound X-Correlation-ID get
    # None and the metadata simply lacks the key.
    effective_cid = correlation_id if correlation_id is not None else get_correlation_id()
    metadata_json = _prepare_metadata(metadata, correlation_id=effective_cid)

    tracer = trace.get_tracer(_TRACER_NAME)
    start_ns = time.monotonic_ns()
    audit_success = False
    with tracer.start_as_current_span(AUDIT_WRITE_SPAN_NAME) as span:
        attrs: dict[str, Any] = {
            "event_type": action,
            "actor_type": actor_type,
            "actor_id": actor_id,
        }
        if target_id is not None:
            attrs["target_id"] = target_id
        if target_kind is not None:
            attrs["target_kind"] = str(target_kind)
        for key, value in attrs.items():
            span.set_attribute(key, value)

        try:
            # Coerce target_kind to str explicitly: asyncpg's codec
            # dispatch keys on ``type(value)`` (not ``str(value)``), so a
            # StrEnum subclass relies on the codec accepting the subclass
            # via duck-typed string semantics. That has worked across
            # asyncpg 0.27-0.29 empirically but is not part of asyncpg's
            # documented contract -- a future minor-version codec
            # tightening (e.g. exact ``type is str`` check) would silently
            # break us. The explicit coercion makes the contract
            # invariant under codec dispatch changes.
            await conn.execute(
                AUDIT_INSERT_SQL,
                actor_type,
                actor_id,
                action,
                target_type,
                target_id,
                str(target_kind) if target_kind is not None else None,
                reason,
                metadata_json,
                normalized_ip,
                user_agent,
            )
            audit_success = True
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR))
            raise
        finally:
            latency_ms = (time.monotonic_ns() - start_ns) / _NS_PER_MS
            span.set_attribute("success", audit_success)
            span.set_attribute("latency_ms", round(latency_ms, 2))


async def record_audit_deduped_async(
    conn: asyncpg.Connection,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    target_kind: TargetKind | str,
    target_type: str | None = None,
    target_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> bool:
    """Insert one immutable row using the dedup INSERT shape.

    Wraps :data:`AUDIT_INSERT_DEDUPED_SQL` so callers do not have to
    write raw SQL with positional args. Applies actor-side validation
    (``_validate_audit_id`` on actor_id, banned-key metadata
    redaction, metadata size cap) and emits an ``audit.write`` OTel
    span. Returns ``True`` when the row was inserted, ``False`` when
    ON CONFLICT skipped the write (re-delivery dedup).

    Closes the S2 LOW-1 footgun where actor_id strings like
    ``"stripe_webhook"`` / ``"kratos_webhook"`` bypass validation when
    callers use raw SQL. ``target_id`` is NOT shape-validated here:
    dedup callers persist external-system IDs (Stripe subscription IDs,
    email hashes) that intentionally do not follow the
    UUID-or-prefix convention. The dedup partial unique index keys on
    ``target_kind`` which IS validated as required.

    The ``target_kind`` argument is required here because the dedup
    partial unique index ``audit_log_content_hash_uidx`` keys on
    ``target_kind`` -- a NULL value would route every kind into the
    same dedup namespace.

    Parameters
    ----------
    conn:
        Active ``asyncpg`` connection.
    actor_type:
        One of ``user``, ``admin``, ``system``, ``hydra_subject``.
    actor_id:
        Opaque actor identifier (UUID or ``system:<name>`` etc.).
    action:
        Event string.
    target_kind:
        Required namespace discriminator. Must be a TargetKind value
        (or its string).
    target_type:
        Optional entity kind label.
    target_id:
        Optional entity identifier. Passed through verbatim --
        intentionally NOT validated, since dedup callers persist
        external-system IDs (Stripe sub_xxx, email hashes).
    metadata:
        Optional JSON-serialisable dict; must carry a
        ``"content_hash"`` key for the dedup partial unique index to
        fire. Banned keys are redacted; the post-redaction payload must
        be <= ``MAX_METADATA_BYTES``.
    """
    # Routes through the same validator as the canonical writer so a
    # future tightening of actor_type / actor_id rules cannot drift
    # between the two paths. The dedup path always requires target_kind
    # (the partial unique index keys on it), so the helper's
    # ``target_id requires target_kind`` invariant is the right contract
    # here as well. target_id is intentionally NOT shape-validated --
    # dedup callers persist external-system IDs (Stripe sub_xxx, email
    # hashes) that do not satisfy the UUID-or-prefix rule.
    _validate_actor_and_target(
        actor_type=actor_type,
        actor_id=actor_id,
        target_id=target_id,
        target_kind=target_kind,
    )

    # See ``record_audit_async`` for ContextVar-default rationale.
    effective_cid = correlation_id if correlation_id is not None else get_correlation_id()
    metadata_json = _prepare_metadata(metadata, correlation_id=effective_cid)

    tracer = trace.get_tracer(_TRACER_NAME)
    start_ns = time.monotonic_ns()
    audit_success = False
    inserted = False
    with tracer.start_as_current_span(AUDIT_WRITE_SPAN_NAME) as span:
        attrs: dict[str, Any] = {
            "event_type": action,
            "actor_type": actor_type,
            "actor_id": actor_id,
        }
        if target_id is not None:
            attrs["target_id"] = target_id
        if target_kind is not None:
            attrs["target_kind"] = str(target_kind)
        for key, value in attrs.items():
            span.set_attribute(key, value)

        try:
            # See ``record_audit_async`` for the asyncpg codec rationale
            # behind the explicit ``str(target_kind)`` coercion. The
            # dedup path makes target_kind required, so we never see
            # None here, but the conditional kept symmetric with the
            # canonical path for grep-safety.
            result = await conn.fetchval(
                AUDIT_INSERT_DEDUPED_SQL,
                actor_type,
                actor_id,
                action,
                str(target_kind) if target_kind is not None else None,
                target_type,
                target_id,
                metadata_json,
            )
            inserted = result is not None
            audit_success = True
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR))
            raise
        finally:
            latency_ms = (time.monotonic_ns() - start_ns) / _NS_PER_MS
            span.set_attribute("success", audit_success)
            span.set_attribute("latency_ms", round(latency_ms, 2))
    return inserted
