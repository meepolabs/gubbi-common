# Changelog

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
