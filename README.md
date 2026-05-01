# gubbi-common

Shared contracts (audit, auth, telemetry) consumed by Gubbi packages
(`journalctl`, `journalctl-cloud`, future siblings).

This is intentionally a tiny package. It holds only the cross-package
definitions that need to stay in sync -- enums, SQL templates, header
builders, allowlists. Everything else lives in the consuming package.

## Install

Distributed as a git dependency. In a consumer's `pyproject.toml`:

```toml
gubbi-common = { git = "ssh://git@github.com/meepolabs/gubbi-common.git", tag = "v0.1.0" }
```

Pin a tag, not a branch. Bump the tag when the contract changes.

## Modules

Populated in subsequent commits as content migrates from sibling repos.

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
