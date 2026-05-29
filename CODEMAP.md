# gubbi-common -- CODEMAP

> Module-level navigation guide for agents and humans working in this repo.

## What this is

`gubbi-common` is the AGPL-3.0 shared library between
[`gubbi`](https://github.com/meepolabs/gubbi) (the MCP server / data
plane) and the proprietary control-plane gateway. Cross-cuts that need a
single canonical home -- audit Action enum + SQL templates, HMAC
gateway-signature envelope, OAuth bearer-challenge builder, Hydra token
claims dataclass, telemetry allowlist, `user_scoped_connection`,
correlation-id helpers -- live here.

Python ~3.12. Optional `db` extra (asyncpg). Pinned by both consumers via
git tag; SemVer'd, changelog enforces a "Consumer impact" line per entry.

## Where it fits

- One library, two consumers. Both consumers pin the same git tag.
- Each module is the single source of truth for its concern. Consumers
  must import from here, not redefine.
- Graduation criteria: a symbol moves into gubbi-common when both
  consumers need it AND the contract is stable enough to share. Anything
  that looks consumer-specific should stay private.

## Repo layout

```
gubbi-common/
  pyproject.toml            Poetry, AGPL-3.0, packages = gubbi_common
  README.md, CHANGELOG.md, CONTRIBUTING.md, CLA.md, LICENSE
  gubbi_common/             Python package (see below)
  tests/                    pytest, asyncio strict mode
  tools/                    helper scripts
  docs/                     contributor + integration docs
```

## Python package modules (`gubbi_common/`)

Per-module public surface comes through each `__init__.py` -- import
those re-exports rather than reaching into submodules.

| Module | Public surface | What it owns |
|---|---|---|
| `constants.py` | `RESOURCE_DOCUMENTATION_URL` | Top-level shared constants. Currently holds the OAuth Protected Resource Metadata documentation URL (RFC 9728 `resource_documentation` field) emitted by both consumers in their `/.well-known/oauth-protected-resource` payloads. Re-exported from the package root. |
| `audit/` | `Action`, `TargetKind`, `record_audit_async`, `record_audit_deduped_async` | Audit Action enum (one canonical list of action strings), audit SQL templates with content-hash dedup keyed on the 5-tuple `(actor_id, target_kind, target_id, action, metadata->>'content_hash')` -- actor_id is part of the key (added in gubbi migration 0031) so dedup is scoped per actor -- and target-kind taxonomy. Both writers emit an `audit.write` OTel span with attributes routed through `safe_set_attributes` against an internal allowlist (`_AUDIT_WRITE_ALLOWLIST`); only `event_type`, `actor_type`, `success`, and `latency_ms` appear on the span -- `actor_id`, `target_id`, and `target_kind` are intentionally absent (they are stored durably on the audit row's columns and must not reach the OTel backend). The dedup partial unique index `audit_log_content_hash_uidx` lives in gubbi's Alembic chain; `tests/integration/conftest.py` vendors a matching `audit_log` DDL pinned via `AUDIT_LOG_DDL_BASED_ON` (currently `20260516_0031`) and a drift-guard test fails CI if the pin falls behind the latest matching migration. |
| `auth/` | `build_bearer_challenge`, gateway-signature surface (`build_signature`, `verify_signature`, `GATEWAY_CONTRACT_VERSION`, `MAX_SKEW_SECONDS`, signature-error classes), `TokenClaims` + Hydra error classes, `build_prm_metadata_url`, `PRMUrlError` | OAuth bearer 401 challenge formatter (RFC 6750 + MCP spec), HMAC gateway-signature envelope (timestamp + canonical request + sig; both consumers must use the same builder), Hydra introspection result dataclass, protected-resource-metadata URL builder. |
| `bootstrap/` | `PgLogProbeMode`, `PgLogProbeError`, `StartupProbe`, `StartupRunner`, `ProbeStatus`, `ProbeResult`, `ProbeOutcome`, `ProbeFailure`, `StartupBudgetExceeded`, `OutcomeCounterCallback`, `RecordedProbe`, `RecordingProbeRunner`; `bootstrap.probes`: `PgLogProbe`, `RedisPingProbe` | Cross-app contract for app-startup probes. `PgLogProbe` is the canonical STRICT/WARN/OFF check for PG log-parameter-capture settings (run at startup so a misconfigured DB fails loud, not silently leaks plaintext into pg_log); the underlying module-private helper is not part of the public surface. `StartupProbe` Protocol + `StartupRunner` orchestrator unify the wider lifespan-probe contract: per-probe `asyncio.timeout`, total-boot-budget pre-flight guard, OTel span emission (`startup.probe.<name>`), deque-buffered `log_tail` capture for failure forensics, optional outcome-counter callback. Non-required FAIL downgrades to WARN on observability rails while `ProbeOutcome.status` stays raw so the lifespan caller can distinguish ran-and-failed from ran-and-warned. `RecordingProbeRunner` is the test helper consumers use to pin canonical probe order in lifespan smoke tests. The `bootstrap.probes` sub-module hosts shared `StartupProbe` wrappers both consumers compose: `PgLogProbe` (catches STRICT-mode `PgLogProbeError` and surfaces it as a structured FAIL with mode + findings diagnostic) and `RedisPingProbe` (PINGs a `redis.asyncio.Redis` client; lets driver exceptions propagate so the runner's central credential-scrubbing path applies). |
| `budget/` | `BudgetHelper`, `PRE_CHARGE_CENTS`, `PRE_CHARGE_LUA`, `budget_key`, `current_period_start`, `dirty_member` | LLM budget primitives: pre-charge Lua script (atomic check-and-debit), Redis key formatters, period-start helper, dirty-set member format. Both consumers share the budget hot-path via this module. |
| `correlation.py` | `CorrelationContext`, `cid_from_scope`, re-exports of `set_correlation_id` / `get_correlation_id` / `reset_correlation_id` | Canonical home for the `correlation_id` envelope shape and the `correlation_id` ContextVar. One import point for both consumers; do NOT extend without updating both. |
| `db/` | `user_scoped_connection`, `MissingUserIdError` | The async context manager that opens an asyncpg transaction, sets `app.current_user_id` GUC + `hnsw.ef_search`, and releases. Both helpers accept a `pool_acquire_timeout_seconds` parameter (default 5 s) so pool exhaustion fails fast rather than hanging indefinitely. RLS depends on this -- both consumers acquire user-scoped connections through this single helper. Optional dependency: requires the `db` extra. |
| `http/` | `client_ip` | XFF + Forwarded header parser. Single canonical implementation; security-sensitive. |
| `middleware/` | `CorrelationIDMiddleware` | ASGI middleware: extract / propagate / emit `X-Correlation-ID` and bind it into structlog contextvars. Tags the root OTel span with `correlation_id` directly (the root span is already open before user middleware runs; child spans are tagged by `CorrelationSpanProcessor`). Used by both consumers' middleware stacks. |
| `telemetry/` | `safe_set_attributes`, `BANNED_KEYS`, `is_banned_key`, `bound_logger`, `configure_otel`, `get_tracer`, `safe_instrument`, `StructuredLogFormatter`, `initialize_logger`, `set_correlation_id` / `get_correlation_id` / `reset_correlation_id`; `CorrelationSpanProcessor` (import via `gubbi_common.telemetry.correlation_processor`) | Per-consumer OTel attribute allowlist (keeps PII out of span attributes), bound-logger surface, OTel SDK config helpers, structlog formatter wired to OTel. `CorrelationSpanProcessor` is a `SpanProcessor` that reads the `correlation_id` ContextVar at `on_start` and stamps it on every span; pass it via `configure_otel(extra_processors=[...])` so the wiring is atomic with provider construction. |
| `tools/` | (CLI scripts; not imported at runtime) | Tooling shipped inside the package. Hosts `check_no_double_prefix`, the canonical lint script both consumers invoke from their pre-commit hooks (replaces the per-repo shims that previously lived in each consumer's `tools/`). |

## Entry points

This is a library -- there's no service to start. Consumers import
specific modules. The two paths agents most often want:

- `from gubbi_common.audit import Action, record_audit_async`
- `from gubbi_common.db import user_scoped_connection`

## Adding a symbol

Two-consumer rule: a symbol graduates into gubbi-common only when it's
needed in BOTH the MCP server and the upstream gateway, and the contract
is stable. New surface area requires:

1. Added to the relevant submodule.
2. Re-exported from the submodule's `__init__.py` (and the package
   `__init__.py` if cross-cutting).
3. CHANGELOG entry with a "Consumer impact" line.
4. Both consumers' pin updated in the same release window (typically
   the next git tag).

## Cross-repo deps

- imported by [`gubbi`](https://github.com/meepolabs/gubbi) (public AGPL)
- imported by the proprietary upstream gateway (private)

No outbound runtime deps on either consumer; this library is the leaf.

## Deeper docs

- [`README.md`](./README.md), [`CHANGELOG.md`](./CHANGELOG.md)
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) -- includes the release-tagging
  policy: not every commit gets a tag; tags mark stable adoption points
- [`CLA.md`](./CLA.md), [`LICENSE`](./LICENSE)
- `docs/` -- per-module integration notes
