# Changelog

Each entry below carries a **Consumer impact** line. Skip-able releases
are still tagged for traceability, but consumers can stay on an older
tag if they don't need the new surface. See
[CONTRIBUTING.md#releasing](./CONTRIBUTING.md#releasing) for the
release-tagging policy: not every commit gets a tag; tags mark stable
adoption points.

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

### Added

- ``gubbi_common.auth.hydra`` module: promoted from gubbi and
  gubbi-cloud consumer repos. Exports ``TokenClaims`` (frozen dataclass
  with ``sub: UUID``, ``scope: str``, ``exp: int``) and the Hydra
  exception hierarchy ``HydraError`` / ``HydraUnreachable`` /
  ``HydraInvalidToken``. The introspector logic and cache protocol stay
  per-repo.
- `HydraError`, `HydraUnreachable`, `HydraInvalidToken` and
  `TokenClaims` re-exported from the `gubbi_common.auth` package-level
  ``__init__.py`` alongside existing auth symbols.

**Non-breaking (additive).** No signature changes to any existing public
API; consumers get new names at read-only cost.

**Consumer impact:** optional adoption. Consumers should migrate away
from their per-repo copies (`gubbi.auth.hydra` and
`gubbi_cloud.auth.hydra`) to the canonical import from
`gubbi_common.auth.hydra`. Upcoming migrations tracked as
CO.29.2-gubbi and CO.29.2-cloud.

## 0.5.1 -- 2026-05-06

### Added

- `set_correlation_id(cid)` now returns a `contextvars.Token` so ASGI/scope-bound
  callers can `reset_correlation_id(token)` in a `finally` block to restore the
  prior value. Prevents cross-request correlation_id leakage without reaching
  for the private `_correlation_id_var` ContextVar.
- `reset_correlation_id(token)` exported from `gubbi_common.telemetry`.

**Non-breaking (additive).** Existing callers that ignored
`set_correlation_id`'s return value continue to work; the prior `-> None`
return type is widened to `-> Token[str | None]`.

**Consumer impact:** optional. Adopt only if you currently import the private
`_correlation_id_var` to manage ContextVar reset semantics in middleware.

## 0.5.0 -- 2026-05-06

### Added

- New canonical `StructuredLogFormatter` class in ``gubbi_common.telemetry.logging``
  (promoted from gubbi and gubbi-cloud). Supports both gubbi-shape (default,
  walk ``record.__dict__``) and cloud-shape (named-attribute lookup via
  ``attributes_attr_name``) output with a stable JSON schema.
- Contextvar-based correlation ID helpers (`set_correlation_id`,
  `get_correlation_id`) exported from ``gubbi_common.telemetry``.
- Trace/span ID propagation via OpenTelemetry context in the formatter,
  with fallback to structlog-injected record attributes for cloud consumers.

**Non-breaking (additive + docs)**

**Consumer impact:** additive. One new public Action constant
(`CONVERSATION_EXTRACTED`); existing callers that used the raw string
`"conversation.extracted"` should swap to the constant. The rest of
the diff is docstring + comment refresh from the consumer-repo
rename. Skip-able if you don't care about the new constant.

### Added

- `Action.CONVERSATION_EXTRACTED = "conversation.extracted"` --
  emitted by the extraction worker when a conversation finishes
  processing. Closes a drift-guard gap surfaced during the gubbi.ai
  rebrand review (gubbi/extraction/jobs/extract_conversation.py was
  using the raw string).

### Changed

- Docstrings, comments, and registry-comment paths updated to reflect
  the consumer-repo rename: `journalctl` -> `gubbi` and `journalctl-cloud`
  -> `gubbi-cloud`. The `gubbi_common` package name is unchanged; no
  imports break.
- Renamed the private drift-guard registry `_JOURNALCTL_REFERENCED` to
  `_GUBBI_REFERENCED` in `gubbi_common.audit.actions`. Both registries
  remain underscore-prefixed (not part of the public API); the rename
  is internal to this package and its tests.

## 0.4.3 -- 2026-05-03

**Non-breaking (additive + correctness)**

**Consumer impact:** optional -- adopt if you write tenant-deprovisioned
or tenant-orphaned audit rows, gate billing on email verification, or
care about IP normalisation in audit_log. Self-hosters with no Stripe
flow do not need this.

### Added

- `Action.TENANT_DEPROVISIONED` (`"tenant.deprovisioned"`) for soft-delete
  audit symmetry with `TENANT_PROVISIONED`.
- `Action.TENANT_ORPHANED` (`"tenant.orphaned"`) for the case where a
  tenant row is orphaned via `ON DELETE SET NULL` on `tenants.user_id`
  (cloud-api migration 0008 / m-real-bugs-cloud).
- `Action.BILLING_EMAIL_UNVERIFIED_BLOCKED` (`"billing.email_unverified_blocked"`)
  -- closes the H-13 follow-up where cloud-api was using the raw
  literal pending an enum entry.
- `BANNED_KEYS` adds modern PII tokens: `phone`, `address`, `prompt`,
  `completion`, `response_text`. Substring-matched, so any attribute
  containing these tokens is dropped from telemetry spans/metrics.
- `gubbi_common.db.user_scoped`: module docstring documenting the RLS
  + HNSW GUC contract; `MIN_HNSW_EF_SEARCH = 1` and
  `MAX_HNSW_EF_SEARCH = 1000` constants replace inline literals.

### Changed

- `record_audit_async` now normalises `ip_address` before storing.
  Three rules collapse near-duplicate representations: IPv4-mapped IPv6
  (`::ffff:127.0.0.1`) is stored as bare IPv4 (`127.0.0.1`); IPv6
  zero-compression is canonicalised (`2001:0db8::0:1` -> `2001:db8::1`);
  scoped IPv6 (`fe80::1%eth0`) is rejected with `ValueError` because
  zone IDs identify the originator's local interface, not a
  cross-machine address, and can carry control chars that poison log
  pipelines. The validator already rejected malformed addresses; this
  adds canonicalisation on the happy path. Existing audit rows are
  unaffected.
- `record_audit_async` invalid-IP `ValueError` now uses `from exc`
  instead of `from None`, preserving the `__cause__` chain for
  forensic debugging.

## 0.4.2 -- 2026-05-02

**Non-breaking (additive)**

### Added

- `gubbi_common.auth.gateway_signature` module: HMAC-SHA256 signer /
  verifier for cross-process auth handoff (`X-Auth-Signature` header),
  plus structured exception hierarchy (`SignatureError`,
  `StaleSignatureError`, `FutureSignatureError`,
  `MalformedTimestampError`, `MismatchedSignatureError`). Exposes
  `GATEWAY_CONTRACT_VERSION = 1` and `MAX_SKEW_SECONDS = 30`. Canonical
  input format:
  `"{version}|{user_id}|{scopes}|{timestamp}|{method}|{path}"`,
  UTF-8-encoded; verifier validates an ISO 8601
  `YYYY-MM-DDTHH:MM:SSZ` UTC timestamp before computing HMAC and uses
  `hmac.compare_digest` for constant-time comparison. Both signer and
  verifier reject any input containing the canonical-input field
  separator `|` to prevent canonicalisation-confusion ambiguity.

Consumer guidance: callers must pass the secret as `bytes` (decode
`hex` / `base64` from env at the call site as appropriate). Both signer
and verifier MUST pin the same `gubbi-common` version -- changing
`GATEWAY_CONTRACT_VERSION` is a contract break that invalidates every
in-flight signature.

## 0.4.1 (2026-05-02)

**Non-breaking (additive + privacy / safety fixes)**

- Added `Action.SUBSCRIPTION_UPDATED` (`"subscription.updated"`) for the
  Stripe `customer.subscription.updated` webhook path.
- Added `Action.USER_DELETED` (`"user.deleted"`) and
  `Action.CLIENT_DELETED` (`"client.deleted"`) for admin / cleanup
  operations.
- `gubbi_common.telemetry.allowlist`: tightened `_is_banned` to apply the
  `BANNED_KEYS` substring check on every key whose suffix is not a true
  derivative quantity. Replaced `TRAILING_MODIFIERS` with
  `DERIVATIVE_MODIFIERS = {"_hash", "_count", "_size", "_len", "_fp",
  "_bytes"}`. Keys ending in `_id` or `_present` are no longer
  structurally exempt -- those suffixes can carry or reveal the
  underlying value, so the BANNED_KEYS check now applies to them.
  `client_user_agent_hash` and other `<banned>_<derivative>` keys
  continue to pass through.
- `gubbi_common.auth.bearer_challenge.build_bearer_challenge`: validates
  inputs against header-injection. Rejects CR / LF / NUL / `"` / `\` in
  any field; restricts `error` to RFC 7230 token grammar; restricts
  `required_scope` to RFC 6749 scope grammar; requires
  `resource_metadata_url` to start with `/` or `https://`. Raises
  `ValueError` on violation. Existing happy-path callers are unaffected.
- Added `tests/test_version_coherence.py`: asserts `pyproject.toml`,
  `gubbi_common.__version__`, and the top `## X.Y.Z` heading in
  `CHANGELOG.md` agree. Pre-tag-push CI gate.

## 0.4.0 (2026-05-01)

**Non-breaking (additive)**

- Added journal-content `Action` constants: `ENTRY_CREATED`,
  `ENTRY_UPDATED`, `ENTRY_DELETED`, `TOPIC_CREATED`,
  `CONVERSATION_SAVED`. Persisted to `audit_log.action`; downstream
  queries can filter `action LIKE 'entry.%'` / `'topic.%'` /
  `'conversation.%'`.

Note: this release shipped with `__version__ = "0.3.0"` in the package
and no CHANGELOG entry; the 0.4.1 release back-fills the CHANGELOG and
realigns `__version__` with `pyproject.toml`.

## 0.3.0 (2026-04-30)

**Non-breaking (additive)**

- Added `gubbi_common.db` submodule with `user_scoped_connection` async
  context manager and `MissingUserIdError`.
- Added optional `asyncpg` dependency (`>=0.29`). Install with
  `pip install gubbi-common[db]` or poetry `extras = ["db"]`.

## 0.2.0 (2026-04-30)

**BREAKING CHANGE**

- `safe_set_attributes` now requires a kw-only `allowlist` parameter
  (`Mapping[str, frozenset[str]]`) injected by the caller. The
  module-global `SPAN_ALLOWLIST` has been removed; each consumer must
  supply its own allowlist dict.
- Unknown span names (not present in the injected allowlist) now drop
  ALL attributes and emit a single DEBUG log entry. Previously they
  fell back to a permissive global deny-list only.
- Added `TRAILING_MODIFIERS` exemption: attribute keys ending in
  `_hash`, `_count`, `_size`, `_bytes`, `_length`, `_present`, `_fp`,
  or `_id` skip the BANNED_KEYS substring check, allowing hashed PII
  forms (e.g. `client_user_agent_hash`) to pass.
- Added `NEVER_EXEMPT_BASES`: even with a trailing modifier, keys whose
  stripped base contains `password`, `secret`, `token`, `credential`,
  or `key` remain banned (e.g. `password_hash`, `session_token_id`).
- Bumped version to 0.2.0.

## 0.1.1 (2026-04-29)

- Initial extracted allowlist from journalctl and journalctl-cloud.
