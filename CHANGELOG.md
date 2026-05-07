# Changelog

Each entry below carries a **Consumer impact** line. Skip-able releases
are still tagged for traceability, but consumers can stay on an older
tag if they don't need the new surface. See
[CONTRIBUTING.md#releasing](./CONTRIBUTING.md#releasing) for the
release-tagging policy: not every commit gets a tag; tags mark stable
adoption points.

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
