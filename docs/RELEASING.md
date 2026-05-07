# Releasing gubbi-common

## Semver policy

PATCH for bug fixes, MINOR for additions, MAJOR for breaking changes.

## Compatibility window

gubbi-cloud may lag gubbi-common by up to 1 minor version; gubbi follows latest.

## Release procedure (manual until automated)

1. Bump version in `pyproject.toml` (root of this repo).
2. Update `CHANGELOG.md` with changes.
3. Commit `chore(release): vX.Y.Z`, tag `vX.Y.Z`, push tag.
4. Open PRs in `gubbi/` and `gubbi-cloud/` updating their `gubbi-common`
   tag pin in `pyproject.toml`. Cloud may lag; gubbi must update.

### Example (from the gubbi-common repo)

```bash
# 1. Bump version in pyproject.toml
#    Edit: version = "X.Y.Z" -> version = "X.Y.(Z+1)" or MINOR/MAJOR bump.

# 2. Update CHANGELOG.md with unreleased changes under the new version heading.

# 3. Commit, tag, push -- this triggers GitHub release assets (wheel/sdist).
git commit -am "chore(release): vX.Y.Z"
git tag v$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['tool']['poetry']['version'])")
git push origin main --tags

# 4. Open PRs in downstream repos updating the pin:
#    gubbi:        PR targeting main with the new tag version pinned.
#    gubbi-cloud:  PR (may lag by up to 1 minor); only if it's safe.
```

## Cross-repo CI explainer

When a PR targets `main`, the workflow
[`.github/workflows/cross-repo-validate.yml`](../.github/workflows/cross-repo-validate.yml)
checks branch changes against each downstream consumer (`gubbi` /
`gubbi-cloud`). It overrides the `gubbi-common` dependency in each downstream's
`pyproject.toml` to use `path = "../gubbi-common"` with `develop = true`, runs
their test suites, and blocks merge if a downstream breakage is detected.

The `gubbi-cloud` matrix entry requires the
`GUBBI_CLOUD_PAT` secret (a GitHub personal access token with `repo` scope)
to be set in this repo's Settings > Secrets. Without it the step skips with a
warning on fork PRs; the gubbi and core `test` jobs still run unconditionally.

## Hyrum's Law -- Deprecation policy

When moving modules from per-repo into `gubbi-common`, consumer code may
depend on transitive import paths (Hyrum's Law: "With a similar number of
consumers, an API structure is just as immutable as the API itself").

See [07-code-organization.md](../reviews/2026-05-04-deep-review/07-code-organization.md)
Part 9.8 for the deprecation-and-compat policy. In short:

- Public module paths in the `gubbi_common` namespace are stable contracts.
- Renaming or moving a public module requires at least one minor-version
  compatibility shim (deprecated import re-export).
- Deprecated shims remain for exactly one minor release cycle, then are
  removed and documented in the changelog under a migration note.
