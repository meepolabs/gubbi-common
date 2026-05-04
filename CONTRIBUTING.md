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

This package is consumed via git tag from sibling repos. **Releases exist
to give consumers a stable point to upgrade to -- not to mark every commit.**
The cardinal rule: ship a release only when a consumer has a reason to
adopt it.

### Tag a release when

- Public API changes (new module, new function, new Action constant, changed signature).
- Bug fix that affects observable behaviour at a call site.
- Security fix consumers should pull.
- Cross-repo contract change (audit_log shape, header format, etc).

### Don't tag (commit to main without a release) when

- Test additions / refactors that don't change runtime behaviour.
- Docstring / comment / README edits.
- Internal refactors that don't change public surface.
- Dev-tooling / pre-commit / CI changes.
- Anything where a consumer asking "should I bump?" would correctly answer "no."

These commits land on main but don't bump version, don't tag, don't
update CHANGELOG. Consumers see them only when their next release-driven
upgrade rolls past them.

### Cutting a release (when warranted)

1. Bump `version` in `pyproject.toml` and `gubbi_common/__init__.py`.
2. Add a CHANGELOG entry. Include a **Consumer impact** line:
   - `Consumer impact: must upgrade -- <reason>` (rare; only for security / contract breaks).
   - `Consumer impact: optional -- adopt if you need <feature>` (most additive releases).
   - `Consumer impact: none -- internal-only` (should not happen; if it does, you probably should not have tagged).
3. Commit + push to main.
4. Tag: `git tag -a v0.x.y -m "..."` then push tag with explicit operator approval.
5. Consumers bump their pinned tag **only when they adopt the new surface.**

### SemVer discipline

- PATCH (`0.x.y`): bug fixes + additive non-breaking changes (new Action constants, new BANNED_KEYS entries, etc).
- MINOR (`0.x.0`): new modules or larger non-breaking surfaces; reserved for batched additive features.
- MAJOR (`x.0.0`): pre-1.0, kept at 0; once stable, breaking changes go here.

Pre-1.0 we treat MINOR (`0.x.0`) as the normal cadence for batched
features and PATCH (`0.x.y`) for individual fixes. Breaking changes
during 0.x bump MINOR (e.g. v0.5.0 will introduce `Action(StrEnum)` --
breaking-ish runtime type change requiring consumer audit).
