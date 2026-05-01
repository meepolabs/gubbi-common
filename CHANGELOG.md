# Changelog

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
