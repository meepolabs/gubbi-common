# Changelog

Each entry below carries a **Consumer impact** line. Skip-able releases
are still tagged for traceability, but consumers can stay on an older
tag if they don't need the new surface. See
[CONTRIBUTING.md#releasing](./CONTRIBUTING.md#releasing) for the
release-tagging policy: not every commit gets a tag; tags mark stable
adoption points.

## 0.13.2 -- 2026-05-21

### Added

- ``gubbi_common.constants.RESOURCE_DOCUMENTATION_URL`` -- new shared
  constant for the public-facing OAuth Protected Resource Metadata
  ``resource_documentation`` field (RFC 9728). Add ``RESOURCE_DOCUMENTATION_URL``
  shared constant so consumers stop duplicating the OAuth Protected
  Resource Metadata docs URL. Re-exported from the top-level
  ``gubbi_common`` package so ``from gubbi_common import
  RESOURCE_DOCUMENTATION_URL`` works.

### Consumer impact

Additive. Both gubbi (``gubbi/oauth/wellknown.py``) and gubbi-cloud
(``gubbi_cloud/api/main.py``) currently hardcode the same literal
``"https://gubbi.ai/docs/mcp"`` in their Protected Resource Metadata
payloads. Bumping to this tag lets both repos replace the literal with
``from gubbi_common import RESOURCE_DOCUMENTATION_URL`` and the URL
moves in one place. No behaviour change until the consumers cut over.

---

## 0.13.1 -- 2026-05-21

### Added

- ``gubbi_common.db.user_scoped_connection`` and
  ``user_scoped_connection_readonly`` now accept a
  ``pool_acquire_timeout_seconds: float`` keyword argument that is
  forwarded as ``pool.acquire(timeout=...)``. Without a timeout, a slow
  DB combined with many concurrent requests can exhaust the pool and
  every request hangs forever waiting on a connection; with this
  argument, asyncpg raises ``asyncio.TimeoutError`` after the budget
  expires and the request returns a clean error rather than piling up.
  Validation mirrors ``hnsw_ef_search``: ``bool`` is rejected (would
  silently coerce to 1.0 / 0.0), non-numeric types raise ``TypeError``,
  zero or negative values raise ``ValueError``.
- ``DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS = 5.0`` -- new module-level
  constant exposing the default budget. Five seconds is generous
  enough to absorb pool warm-up and brief contention spikes (healthy
  acquires are sub-millisecond) while well under typical HTTP request
  budgets, so the timeout only fires under genuine pool exhaustion or
  DB-down conditions.

### Consumer impact

Additive. Existing callers that pass nothing inherit the 5.0 second
default; previously their acquires were unbounded and could hang
indefinitely on a saturated pool. No changes are required in gubbi or
gubbi-cloud to pick up the new behaviour, but per-call overrides are
available wherever a specific path needs a tighter or looser budget.

---

## 0.13.0 -- 2026-05-14

### Added

- ``gubbi_common.correlation`` -- canonical home for the
  ``correlation_id`` envelope shape. Exposes ``CorrelationContext``
  (frozen dataclass; one ``correlation_id: str`` field today, deliberate
  YAGNI on extra fields), ``cid_from_scope(scope)`` (centralises the
  ASGI-scope byte-iteration helper that gubbi-cloud's auth_middleware
  and subscription_middleware previously duplicated), and re-exports of
  ``set_correlation_id`` / ``get_correlation_id`` /
  ``reset_correlation_id`` (canonical contextvar handles, aliased from
  ``gubbi_common.telemetry.logging`` so downstream code has one import
  point). Closes B5 Q1=A.
- ``tools/check_gubbi_common_purity.py`` -- new lint script: walks
  every ``.py`` file under ``gubbi_common/`` and FAILS CI on any
  RUNTIME import from a deny-list of framework packages (fastapi,
  starlette, uvicorn, sqlalchemy, redis, asyncpg, anthropic, arq,
  httpx, mcp, stripe, pgvector, bcrypt). Imports inside
  ``if TYPE_CHECKING:`` are exempt; the ``else:`` branch is treated as
  RUNTIME (it IS runtime). One ALLOW exception is documented inline
  for ``db/user_scoped.py`` (asyncpg is required at runtime there;
  declared as the ``[db]`` optional extra in pyproject). Wired into
  ``.github/workflows/test.yml`` as a lint-job step. Closes B5 Q3=A+C.

### Changed

- ``gubbi_common.middleware.correlation`` -- ``starlette.types``
  imports moved under ``if TYPE_CHECKING:``. Functionally a no-op
  (those are pure type aliases), but the module is now starlette-free
  at runtime per the new purity rule.

### Consumer impact

Both gubbi and gubbi-cloud should bump their ``gubbi-common`` git pin
to this tag and import correlation_id helpers from
``gubbi_common.correlation`` going forward.
``gubbi_common.telemetry.logging`` continues to expose the same
helpers; the new module just adds a single canonical import point and
the typed envelope.

## 0.12.0 -- 2026-05-14

### Added

- ``gubbi_common.telemetry.otel.configure_otel(...)`` accepts new
  ``service_version`` and ``deployment_environment`` kwargs. Both are
  applied to the OTel ``Resource`` defaults; ``OTEL_RESOURCE_ATTRIBUTES``
  env var still overlays per OTel spec. Default to ``None`` so existing
  callers continue to work without changes -- pass each repo's
  ``__version__`` and ``settings.app_env`` to enable per-deploy /
  per-env trace slicing in HyperDX.

### Changed

- mypy flag set converged across the three Python repos (B4 Q1=A): added
  ``disallow_untyped_calls``, ``disallow_any_generics``,
  ``strict_equality``, ``extra_checks``, ``no_implicit_reexport``. No
  fix-up sites needed in gubbi-common -- the new flags passed cleanly.
- ``trace_get_current_span()`` return annotated as ``Span`` (was
  inferred ``Any``). B4 Q2 closing C2 MEDIUM #10.

### Docs

- ``client_ip.py`` module docstring: rephrase the historical-bug note
  around "rightmost XFF (DEC-086 rule 4)" -- the prior wording said
  "leftmost" in a context that misled future readers about the fix
  direction.
- New regression test ``tests/telemetry/test_allowlist.py::test_content_hash_is_not_banned``
  pins the audit-log dedup key against future changes to
  ``DERIVATIVE_MODIFIERS`` or the order-of-checks in ``is_banned_key``.

**Consumer impact:** gubbi + gubbi-cloud should bump their pin to this
version to pick up the new ``configure_otel()`` kwargs. The kwargs are
optional with safe defaults, so consumers that don't pass them get
identical behavior to 0.11.0.

---

## 0.11.0 -- 2026-05-13

### Added

- ``gubbi_common.audit.sql.record_audit_deduped_async(...)`` -- typed
  wrapper around ``AUDIT_INSERT_DEDUPED_SQL`` so dedup callers do not
  have to write raw SQL with positional args. Applies actor_id
  validation, banned-key metadata redaction, and metadata size cap.
  Emits an ``audit.write`` OTel span. Closes the S2 LOW-1 footgun where
  actor_id strings (``"stripe_webhook"`` / ``"kratos_webhook"``) bypass
  ``_validate_audit_id`` when callers reach for the raw SQL constant.
- ``gubbi_common.telemetry.otel.safe_instrument(name, factory)`` -- shared
  wrapper for auto-instrumentor wiring. Logs a DEBUG line on success and
  swallows + WARNINGs on failure so a broken instrumentor (driver
  missing, signature drift) cannot crash startup. Both gubbi and
  gubbi-cloud call this helper instead of duplicating per-instrumentor
  try/except blocks (S8 H3 + S8 M-2). A7 Q1.

### Changed

- ``gubbi_common.audit.sql.AUDIT_INSERT_SQL`` is now the canonical
  10-column INSERT including ``target_kind``. The argument was already
  accepted by ``record_audit_async`` but silently dropped on the floor
  -- it now persists on the row. Closes S2 MEDIUM (record_audit_async
  target_kind footgun). A3 Q1.
- ``record_audit_async`` now emits an ``audit.write`` OTel span carrying
  ``event_type``, ``target_id``, ``actor_type``, ``success``, and
  ``latency_ms`` (gubbi's existing span shape). Cloud webhook + admin
  audit writes get spans for free without per-site instrumentation.
  A3 Q1.

### Removed

- ``AUDIT_INSERT_SHORT_SQL`` -- the legacy 6-column shape used by the
  pre-consolidation Kratos / billing call sites. All call sites migrated
  to ``record_audit_async`` (canonical) or ``record_audit_deduped_async``
  (dedup) in the A3 cross-repo bump.
- ``AUDIT_INSERT_SQL_RICH`` -- the 7-column shape carrying
  ``occurred_at`` for wire-timestamp parity. The DB default
  ``occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()`` covers the same
  observation window with sub-millisecond drift; callers migrated to
  the canonical writer.

### Consumer impact

- gubbi: drop the local ``_AUDIT_INSERT_SQL`` constant in
  ``gubbi/audit/sql.py``; canonical path now lives in this package.
  Bump the gubbi-common pin to 0.11.0.
- gubbi-cloud: migrate every ``AUDIT_INSERT_SHORT_SQL`` /
  ``AUDIT_INSERT_SQL_RICH`` call site off the raw constants to
  ``record_audit_async`` / ``record_audit_deduped_async``. Bump the
  gubbi-common pin to 0.11.0.

## 0.10.0 -- 2026-05-11

### Added

- ``gubbi_common.auth.prm.build_prm_metadata_url(resource_url, *,
  legacy_suffix=True) -> str`` -- single source of truth for RFC 9728
  Protected Resource Metadata URL composition. Validates the input is
  an absolute http(s) URL (raises ``PRMUrlError`` otherwise),
  normalises trailing slashes, and returns
  ``<origin>/.well-known/oauth-protected-resource[/mcp]``. The
  ``legacy_suffix=True`` default preserves DEC-083 cutover compat;
  flipping the default to ``False`` is tracked as backlog item
  ``prm-legacy-suffix-cutover``. Closes C-009 (PRM URL coherence broken
  across cloud-api and gubbi: formula was duplicated across at least
  four call sites with subtly different concatenation, no shared
  helper). Re-exported from ``gubbi_common.auth``.
- ``gubbi_common.http.client_ip(request, *, trust_forwarded_headers)
  -> str | None`` -- DEC-086-locked client-IP extractor. RIGHTMOST
  X-Forwarded-For when ``trust_forwarded_headers=True`` (the trusted
  proxy stamp); socket address otherwise; ``None`` when neither is
  available. Promoted verbatim from gubbi-cloud's
  ``webhooks/kratos/_auth.py:_extract_client_ip`` to close the
  recurring bug where the gubbi-side copy at ``oauth/forms.py``
  silently flipped to LEFTMOST XFF (DEC-086 rule 4 violation).
  ``trust_forwarded_headers`` is keyword-only by design so the policy
  is per-call visible at every site.
- 5 new ``Action`` enum members for the M4 Stripe webhook surface
  (B4 wiring lands in cloud-api once the SHA-pin promotes them):
  ``SUBSCRIPTION_TRIAL_ENDING_NOTICED`` (``subscription.trial_ending.noticed``),
  ``SUBSCRIPTION_PAYMENT_FAILED`` (``subscription.payment_failed``),
  ``SUBSCRIPTION_PAYMENT_SUCCEEDED`` (``subscription.payment_succeeded``),
  ``SUBSCRIPTION_PAYMENT_ACTION_REQUIRED``
  (``subscription.payment_action_required``), ``CHECKOUT_EXPIRED``
  (``checkout.session.expired``). All five registered in
  ``_CLOUD_REFERENCED`` with their planned cloud-side wiring sites.
  ``test_action_iterable_count_guard`` count bumped from 29 to 34.

### Tests

- ``tests/auth/test_prm.py`` -- 7 cases covering legacy/canonical
  shapes, trailing-slash normalisation, relative-URL rejection (raises
  ``PRMUrlError``), and the gubbi self-host path-prefix shape.
- ``tests/http/test_client_ip.py`` -- 9 cases covering rightmost-XFF
  selection, fallback-on-invalid-IP, untrusted-header ignore, IPv6
  parsing, whitespace XFF, and ``None`` when no source is recoverable.
- ``tests/audit/test_actions.py::test_new_subscription_action_members_present``
  -- pins the 5 new Stripe-webhook member names + values.

### Cross-refs

- C-009 (PRM URL coherence): ``gubbi_common.auth.prm.build_prm_metadata_url``
  is the helper. Both cloud-api and gubbi consume it; the
  ``legacy_suffix=True`` default is gated by DEC-083 cutover policy.
- DEC-086 (client-IP extraction): ``gubbi_common.http.client_ip``
  is the canonical implementation. Rule 4 (rightmost XFF when
  trusted) is locked here.
- M2-M4 HIGH B4 (Stripe ``@audited(audit_fn=...)`` retrofit) imports
  the 5 new ``Action`` members; B4 is hard-blocked on this release
  shipping and the SHA-pin landing in both consumers.

### Consumer impact

Additive. Two new helpers, 5 new Action members, no behaviour change
for existing imports. Both consumers (gubbi, gubbi-cloud) re-pin to
this SHA in a coordinated Wave 1.5 step (M2-M4 HIGH plan) and rewire
4 call sites (auth_middleware, gubbi/main.py, oauth/forms.py,
kratos/_auth.py) to the new helpers; the consumer rewires are tracked
under B2-T5, NOT in this release.

## 0.9.1 -- 2026-05-11

### Fixed

- ``AUDIT_INSERT_DEDUPED_SQL`` now writes the 7-column tuple
  ``(actor_type, actor_id, action, target_kind, target_type, target_id,
  metadata)`` with ``ON CONFLICT (target_kind, target_id, action,
  (metadata->>'content_hash'))``. Restores compatibility with the
  partial unique index ``audit_log_content_hash_uidx`` rebuilt by gubbi
  Alembic migration 0020. Prior 6-column shape produced 42P10 against
  any mig-0020 DB.

### Added

- ``gubbi_common.audit.TargetKind`` -- ``StrEnum`` of the canonical
  namespace discriminators (``topic``, ``entry``, ``conversation``,
  ``extraction_job``, ``user``, ``subscription``) persisted to
  ``audit_log.target_kind``. Mirrors the ``Action`` enum shape, with
  ``_GUBBI_TARGET_KINDS`` / ``_CLOUD_TARGET_KINDS`` consumer-reference
  drift-guard frozensets.
- ``record_audit_async`` now takes a ``target_kind`` keyword argument
  and raises ``ValueError`` if ``target_id`` is supplied without
  ``target_kind``. Mirrors the invariant gubbi's ``record_audit``
  enforces.

### Tests

- ``test_dedup_unique_index_column_composition`` -- pins the 4-tuple
  ``(target_kind, target_id, action, (metadata->>'content_hash'))`` on
  the partial unique index via ``pg_index`` + ``pg_get_indexdef``.
- ``test_dedup_distinguishes_target_kinds`` -- regression test
  exercising mig 0020's actual motivation: same ``(target_id, action,
  content_hash)`` with different ``target_kind`` must not collide.
- ``test_audit_ddl_based_on_matches_latest_migration`` plus the new
  ``AUDIT_LOG_DDL_BASED_ON`` constant -- glob-scans the gubbi sibling
  for ``*audit_log*.py`` Alembic revisions and asserts the vendored
  ``AUDIT_LOG_DDL`` pin is current.

### Consumer impact

Both gubbi and gubbi-cloud must pass ``target_kind`` on every audit
write that carries a ``target_id`` (otherwise ``record_audit_async``
raises ``ValueError``). Cross-repo atomic re-pin lands in a follow-up
PR per the locked C-1/C-2 plan.

## 0.9.0 -- 2026-05-11

### Added

- ``gubbi_common.db.user_scoped_connection_readonly`` -- read-only
  scoped connection variant. Skips ``conn.transaction()`` and uses
  session-scoped ``set_config(..., false)`` for the RLS GUCs; intended
  for read paths (semantic search, list endpoints) where transaction
  overhead is unwanted. Pairs with a ``RESET`` in the finally block to
  prevent GUC bleed across pool checkouts.
- ``gubbi_common.telemetry.is_banned_key`` -- public promotion of the
  former private ``_is_banned`` classifier. The legacy underscore name
  is kept as a deprecation alias for one minor release; remove in
  0.10.0.
- ``gubbi_common.bootstrap.pg_log_probe`` -- inspects
  ``log_statement``, ``log_min_duration_statement``,
  ``log_parameter_max_length``, ``auto_explain.log_min_duration``, and
  ``pg_stat_statements.track`` for loud configurations that would
  capture statement text or bound parameters in cluster logs.
  ``probe_pg_log_settings(pool, mode=...)`` accepts ``STRICT`` (raise),
  ``WARN`` (log), or ``OFF`` (skip) via a ``PgLogProbeMode`` StrEnum or
  bare string. Consumers wire the env-var policy themselves; this
  module does not read the environment.
- ``gubbi_common.audit.sql.MAX_METADATA_BYTES`` -- 4096-byte hard cap
  on the JSON-encoded ``audit_log.metadata`` payload.

### Changed

- ``gubbi_common.audit.sql.record_audit_async`` now redacts banned-key
  values (per ``is_banned_key``) recursively before serialisation and
  rejects metadata that exceeds ``MAX_METADATA_BYTES`` after redaction.
  Banned-key values become the literal ``"[REDACTED]"``. Callers whose
  payload is genuinely large must summarise (counts, hashes, IDs)
  rather than embedding full content.
- ``gubbi_common.audit.sql.record_audit_async`` now validates
  ``actor_id`` and ``target_id`` shape: each must be a UUID string or
  start with one of ``system:``, ``script:``, ``hydra_subject:``.
  Empty / whitespace values and unknown shapes raise ``ValueError``.
  Technically breaking for callers that supplied malformed identifiers;
  the pre-flight grep across both consumer repos found zero offenders.
- ``gubbi_common.audit.actions.Action`` is now a ``StrEnum`` with an
  explicit ``__str__`` override that returns ``self.value``. The
  override locks ``f"{Action.X}"`` and ``str(...)`` parity across
  Python 3.11 (default ``"Action.LOGIN_FAILED"``) and 3.12 (default
  ``"login_failed"``); without the override an interpreter upgrade
  silently changes downstream string formatting.
- ``gubbi_common.db.user_scoped_connection`` now ``RESET``s
  ``app.current_user_id`` and ``hnsw.ef_search`` in a finally block on
  context exit. Each RESET runs in its own try/except so a failure in
  one cleanup step does not skip the other and never masks the
  caller's exception.
- ``hnsw.ef_search`` setup tolerates ``UndefinedObjectError``
  (pgvector not loaded) by logging a warning and continuing rather
  than failing the request. Non-vector queries no longer require
  pgvector to be installed.
- ``hnsw_ef_search`` argument is now strictly type-checked: ``bool``,
  ``str``, and ``float`` are rejected with ``TypeError`` (previously
  silently coerced via ``int(...)``).

### Fixed

- Removed the dead ``try: import asyncpg`` guard inside
  ``user_scoped_connection``; ``asyncpg`` is already imported at module
  scope (consumers must install the ``[db]`` extra).

### Migration notes

Consumers MUST grep for ``f"{Action.X}"`` and ``str(Action.X)`` and
verify the desired output is the bare value (``login_failed``, not
``Action.LOGIN_FAILED``). The ``__str__`` override picks the bare value
on both 3.11 and 3.12; consumers running 3.11 with un-overridden
formatting may have been relying on the qualified form. Pre-flight
sweep across both consumer repos found zero hits.

Audit-metadata callers should verify that any payload exceeding 4096
bytes JSON-encoded is summarised. The cap is enforced after redaction;
the largest-metadata candidates (Stripe webhook, Kratos webhook,
extraction-job completion) are well under the limit per pre-flight
inspection.

**Consumer impact:** primarily additive (new symbols) plus three
hardening changes that are technically breaking for malformed callers
(actor/target id shape, oversized metadata, strict ``int`` for
``hnsw_ef_search``). The pre-flight greps for each found zero offenders
in gubbi or gubbi-cloud; landing the bump should be safe for both
consumers without code changes. The ``_is_banned`` deprecation alias
keeps current imports working for one minor.

## 0.8.0 -- 2026-05-10

### Added

- ``Action.EXTRACTION_JOB_CREATED``, ``Action.EXTRACTION_JOB_COMPLETED``,
  ``Action.EXTRACTION_JOB_FAILED`` constants in
  ``gubbi_common.audit.actions`` for extraction-tracking audit events.
  All three are registered in ``_GUBBI_REFERENCED`` (citing their
  planned call sites in the extraction-tracking rework).

- New ``gubbi_common.budget`` package promoting shared LLM budget
  primitives from ``gubbi_cloud.gateway``:

  - ``PRE_CHARGE_CENTS: Final[int] = 50`` -- default per-extraction
    pre-charge estimate in cents.
  - ``PRE_CHARGE_LUA: Final[str]`` -- the atomic Lua script that debits
    ``used_cents`` from the Redis budget hash only if ``used + estimated
    <= cap``, marks the bucket dirty, and refreshes the TTL.
  - ``current_period_start() -> date`` -- returns the UTC first-of-month
    for the current instant (D10: UTC-anchored).
  - ``budget_key(user_id, period_start) -> str`` -- formats the Redis hash
    key ``budget:{user_id}:{period_start}``.
  - ``dirty_member(user_id, period_start) -> str`` -- formats the member
    string ``{user_id}:{period_start}`` used in the ``budget:dirty`` SET.
  - ``BudgetHelper(*, redis, pre_charge_script)`` -- thin facade exposing
    two methods: ``pre_charge`` (runs Lua; returns True/False) and
    ``record_actual_cost`` (HINCRBY delta, SADD dirty, EXPIRE 3600).
    Negative delta (refund) is fully supported.

**Consumer impact:** additive. Existing imports are unaffected. Consumers
migrating from ``gubbi_cloud.gateway.budget_middleware`` can replace
local copies of ``PRE_CHARGE_CENTS``, ``PRE_CHARGE_LUA``,
``current_period_start()``, and the budget/dirty key formatters with
imports from ``gubbi_common.budget``. The ``_RedisClient`` /
``_RedisScript`` Protocol shapes are internal to
``gubbi_common.budget.helper``; consumers that need to type their own
Redis client stubs should copy the Protocol definitions or import from
the internal module path with the understanding that it is not part of
the stable public API.

## 0.7.2 -- 2026-05-09

### Changed

- chore(deps): bump pytest 8 -> 9 + pytest-asyncio 0.25 -> 1.x
  (closes dependabot CVE-2025-71176 / GHSA-6w46-j5rx-g56g; pytest
  <9.0.3 had world-readable ``/tmp/pytest-of-{user}`` paths
  exploitable on shared multi-user Linux hosts).

**Consumer impact:** dev-only. Consumers MUST harmonize their own
``pytest`` and ``pytest-asyncio`` pins to the same floors when bumping
to this version. pytest 9 requires pytest-asyncio >= 1.x (resolver-
enforced); pytest-asyncio 1.x changed default ``loop_scope`` semantics
for ``@pytest.mark.asyncio`` -- consumers running ``asyncio_mode =
"strict"`` with explicit per-test marks (gubbi-common's pattern) are
unaffected; consumers running ``asyncio_mode = "auto"`` should audit
class-level marks and any ``event_loop`` fixture overrides.

## 0.7.1 -- 2026-05-09

### Added

- ``gubbi_common.telemetry.bound_logger(request)`` -- structlog logger
  factory that pre-binds ``correlation_id`` (from gubbi-common's
  ContextVar) and ``user_id`` / ``tenant_id`` (from ``request.state``)
  for any code path running under a Starlette request scope. Missing
  values are simply absent from the bound dict (NOT bound as ``None``),
  so log calls in early-pipeline middleware before auth/subscription
  bind those values still work cleanly. Consolidates ~10 lines of
  duplicated binding logic that would otherwise live in each consumer
  (CO.50 prep).

**Non-breaking (additive).** No signature changes to any existing
public API.

**Consumer impact:** optional. Per-repo migrations land as CO.50-gubbi
and CO.50-cloud, which adopt ``bound_logger`` in route handlers and
standardise logger naming to ``structlog.get_logger(__name__)``.

## 0.7.0 -- 2026-05-06

### Added

- ``gubbi_common.middleware.CorrelationIDMiddleware`` -- ASGI middleware
  promoted from gubbi and gubbi-cloud (CO.29.4). Manages the request
  ``correlation_id`` contextvar with optional ``echo_header`` and
  ``span_attribute_setter`` callback parameters. Stays free of FastAPI
  and OTel coupling -- consumers wire their own attribute allowlist
  via the callback.
- ``gubbi_common.telemetry.otel.configure_otel(service_name, endpoint, *,
  enabled=True)`` and ``get_tracer()`` -- OTel SDK wiring promoted from
  gubbi-cloud (CO.29.3). Auto-instrumentors stay in consumers (FastAPI,
  asyncpg, redis, httpx remain per-repo concerns).
- ``gubbi_common.telemetry.logging.initialize_logger(logger_name,
  log_dir="logs")`` -- structlog setup promoted from gubbi (CO.29.5).
  Includes the ``_add_otel_context`` processor that enriches every log
  event with ``correlation_id``, ``trace_id``, and ``span_id``.

### Changed

- Declared previously-implicit runtime deps in ``pyproject.toml``:
  ``starlette``, ``structlog``, ``opentelemetry-api``,
  ``opentelemetry-sdk``, ``opentelemetry-exporter-otlp-proto-grpc``.
  v0.5.0 and v0.6.0 had a latent gap -- consumers got these
  transitively via ``fastapi`` / ``opentelemetry-instrumentation-*``,
  but a fresh ``poetry install`` of ``gubbi-common`` on a clean machine
  would have failed with ``ModuleNotFoundError``. Closing the gap now.
- ``_get_otel_ids`` removed from ``gubbi_common.telemetry.logging.__all__``
  (still importable as a private helper; the leading underscore already
  signaled non-public status).

**Non-breaking (additive).** No signature changes to any existing
public API.

**Consumer impact:** optional per-module adoption. Per-repo migrations
land as Batch 2: CO.29.3-{gubbi,cloud}, CO.29.4-{gubbi,cloud},
CO.29.5-{gubbi,cloud}. Consumers still on 0.6.x continue to work.

## 0.6.0 -- 2026-05-06
- Promoted ``gubbi_common.auth.hydra`` (TokenClaims dataclass + Hydra exception hierarchy) from gubbi / gubbi-cloud.

## 0.5.1 -- 2026-05-06
- ``set_correlation_id`` returns a ``contextvars.Token`` and exports ``reset_correlation_id`` so middleware can restore the prior value in finally.

## 0.5.0 -- 2026-05-06
- New ``StructuredLogFormatter`` plus contextvar-based ``set_correlation_id`` / ``get_correlation_id`` and trace/span ID propagation in ``gubbi_common.telemetry.logging``; added ``Action.CONVERSATION_EXTRACTED``.

## 0.4.3 -- 2026-05-03
- Added tenant lifecycle / billing audit constants (``TENANT_DEPROVISIONED``, ``TENANT_ORPHANED``, ``BILLING_EMAIL_UNVERIFIED_BLOCKED``); ``record_audit_async`` normalises ``ip_address`` (IPv4-mapped IPv6, IPv6 zero-compression, scoped-IPv6 rejection); BANNED_KEYS expanded with modern PII tokens.

## 0.4.2 -- 2026-05-02
- New ``gubbi_common.auth.gateway_signature`` HMAC-SHA256 signer / verifier for cross-process auth handoff (``GATEWAY_CONTRACT_VERSION = 1``, 30s skew window, structured exception hierarchy).

## 0.4.1 (2026-05-02)
- Added ``Action.SUBSCRIPTION_UPDATED`` / ``USER_DELETED`` / ``CLIENT_DELETED``; tightened the BANNED_KEYS / DERIVATIVE_MODIFIERS rule and added header-injection validation to ``build_bearer_challenge``.

## 0.4.0 (2026-05-01)
- Added journal-content ``Action`` constants (``ENTRY_CREATED`` / ``ENTRY_UPDATED`` / ``ENTRY_DELETED`` / ``TOPIC_CREATED`` / ``CONVERSATION_SAVED``).

## 0.3.0 (2026-04-30)
- Added ``gubbi_common.db`` submodule with ``user_scoped_connection`` async context manager and the optional ``[db]`` asyncpg extra.

## 0.2.0 (2026-04-30)
- BREAKING: ``safe_set_attributes`` now requires a kw-only injected ``allowlist`` (module-global ``SPAN_ALLOWLIST`` removed); added ``TRAILING_MODIFIERS`` exemptions and ``NEVER_EXEMPT_BASES`` reinforcement.

## 0.1.1 (2026-04-29)
- Initial extracted allowlist from journalctl and journalctl-cloud.
