"""Locate the sibling gubbi repo's Alembic versions directory.

The vendored ``audit_log`` fixture in ``tests/integration/conftest.py``
mirrors gubbi's migration chain, and several tests cross-check it
against the real migration source. Finding that source by counting
parent directories breaks the moment the tests run from a Git worktree,
whose checkout is nested arbitrarily deep below the main repo -- the
drift guard then skips silently and the staleness it exists to catch
ships unnoticed.

This module resolves the directory from candidate anchors instead:
the repo's own working tree, the Git *common* directory (identical for
a worktree and its main checkout, so worktree nesting cannot move it),
and each ancestor of both. The first candidate that looks like gubbi's
versions directory wins.

``REQUIRE_SIBLING_ENV`` turns absence into an error rather than a skip.
The CI integration lane sets it after checking out a pinned revision:
there, a missing sibling means the checkout step regressed, which must
fail loudly. An ordinary local run without the sibling still skips.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Final

__all__ = [
    "GUBBI_VERSIONS_RELATIVE",
    "REQUIRE_SIBLING_ENV",
    "is_versions_dir",
    "iter_sibling_candidates",
    "resolve_gubbi_versions_dir",
    "sibling_required",
]

# Path of the versions directory relative to a gubbi checkout root.
GUBBI_VERSIONS_RELATIVE: Final[tuple[str, ...]] = ("gubbi", "alembic", "versions")

# Directory name a gubbi checkout is expected to occupy next to this repo.
_GUBBI_DIR_NAME: Final[str] = "gubbi"

# Set to "1" in the CI lane that checks out the pinned sibling revision:
# absence becomes a hard failure instead of a skip.
REQUIRE_SIBLING_ENV: Final[str] = "REQUIRE_GUBBI_MIGRATIONS"

# A directory only counts as gubbi's versions directory if it holds at
# least one Alembic revision. An empty directory left behind by a failed
# checkout must not satisfy the resolver.
_REVISION_GLOB: Final[str] = "*.py"


def is_versions_dir(candidate: Path) -> bool:
    """Return True when *candidate* is a populated Alembic versions directory."""
    if not candidate.is_dir():
        return False
    return any(path.name != "__init__.py" for path in candidate.glob(_REVISION_GLOB))


def _git_common_dir(start: Path) -> Path | None:
    """Return the Git common directory for *start*, or None outside a repo.

    The common directory is shared between a worktree and its main
    checkout, so it anchors the search at the same place regardless of
    how deeply the worktree is nested.
    """
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=start,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    output = completed.stdout.strip()
    if not output:
        return None
    return Path(output)


def iter_sibling_candidates(start: Path) -> list[Path]:
    """Return ordered candidate versions directories for *start*.

    Anchors, in order: the working tree containing *start*, then the Git
    common directory's parent (worktree-invariant), then the ancestors of
    both. Every anchor contributes ``<anchor>/gubbi/gubbi/alembic/versions``
    and ``<anchor>/gubbi/alembic/versions`` -- the latter covers an anchor
    that already IS the gubbi checkout root. Ordering is deterministic and
    duplicates are dropped, so the result is directly testable.
    """
    anchors: list[Path] = []

    def add_anchor(path: Path) -> None:
        resolved = path.resolve()
        if resolved not in anchors:
            anchors.append(resolved)

    start = start.resolve()
    add_anchor(start)
    for parent in start.parents:
        add_anchor(parent)

    common_dir = _git_common_dir(start)
    if common_dir is not None:
        # ``.../<repo>/.git`` -> ``.../<repo>`` -> its ancestors.
        add_anchor(common_dir.parent)
        for parent in common_dir.parent.parents:
            add_anchor(parent)

    candidates: list[Path] = []
    for anchor in anchors:
        for prefix in ((_GUBBI_DIR_NAME,), ()):
            candidate = anchor.joinpath(*prefix, *GUBBI_VERSIONS_RELATIVE)
            if candidate not in candidates:
                candidates.append(candidate)
    return candidates


def resolve_gubbi_versions_dir(start: Path | None = None) -> Path | None:
    """Return gubbi's Alembic versions directory, or None when absent.

    *start* defaults to this file's directory, so the resolver works the
    same whether pytest was invoked from the repo root or elsewhere.
    """
    origin = Path(__file__).resolve().parent if start is None else start
    for candidate in iter_sibling_candidates(origin):
        if is_versions_dir(candidate):
            return candidate
    return None


def sibling_required() -> bool:
    """Return True when a missing sibling checkout must fail, not skip."""
    return os.environ.get(REQUIRE_SIBLING_ENV) == "1"
