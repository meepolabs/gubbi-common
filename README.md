# gubbi-common

Shared contracts (audit, auth, telemetry) consumed by Gubbi packages
(`journalctl`, `journalctl-cloud`, future siblings).

This is intentionally a tiny package. It holds only the cross-package
definitions that need to stay in sync -- enums, SQL templates, header
builders, allowlists. Everything else lives in the consuming package.

## Install

Distributed as a git dependency. In a consumer's `pyproject.toml`:

```toml
gubbi-common = { git = "ssh://git@github.com/meepolabs/gubbi-common.git", tag = "v0.4.3" }
```

Pin a tag, not a branch.

### When to bump the pinned tag

Bump only when you need something the new tag introduces -- a new Action
constant, a contract fix, a security patch. Tags mark stable adoption
points, not every commit. If your consumer works correctly on the tag
you're on and you don't need any of the new surface, **stay there**.
Skipping releases is a feature.

Each CHANGELOG entry carries a `Consumer impact:` line stating whether
the upgrade is required, optional, or internal-only. See
[CONTRIBUTING.md#releasing](./CONTRIBUTING.md#releasing) for the
release-tagging policy.

## Modules

### `gubbi_common.telemetry`

OTel span attribute filtering (`safe_set_attributes`, allowlist contracts).

### `gubbi_common.db` (optional extra: `[db]`)

User-scoped asyncpg connection helper (`user_scoped_connection`,
`MissingUserIdError`). Requires asyncpg. Install with:

```toml
# pyproject.toml (poetry)
gubbi-common = { git = "...", tag = "v0.3.0", extras = ["db"] }
```

## Develop

```
poetry install
poetry run pre-commit install
poetry run pytest
poetry run pre-commit run --all-files
```

## License

AGPL-3.0-or-later. See [LICENSE](./LICENSE).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CLA.md](./CLA.md).
