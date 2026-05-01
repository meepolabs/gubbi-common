# Contributing to gubbi-common

Thanks for your interest. Before submitting a PR:

1. Read [CLA.md](./CLA.md). Submitting a PR signals your agreement to
   its terms.
2. Set up the dev environment:
   ```
   poetry install
   poetry run pre-commit install
   ```
3. Add tests for new behaviour. Aim for 80%+ coverage.
4. Run all checks locally before pushing:
   ```
   poetry run pre-commit run --all-files
   poetry run pytest
   ```
5. Keep PRs small and focused. One logical change per PR.
6. Use conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`,
   `chore:`, `perf:`, `ci:`).

For larger changes, open an issue first to discuss the approach.

## Releasing

This package is consumed via git tag from sibling repos. To cut a release:

1. Bump `version` in `pyproject.toml` and `gubbi_common/__init__.py`.
2. Update CHANGELOG (when one exists).
3. Tag: `git tag v0.x.y && git push --tags`.
4. Update consumer `pyproject.toml` files to point at the new tag.
