"""Tests for the sibling-repo resolver.

The resolver exists because a fixed parent-depth path silently misses the
gubbi checkout when the tests run from a Git worktree, which turns the
staleness guards into skips. These tests build synthetic trees -- a main
checkout, a nested worktree, and a tree with no sibling -- so the
worktree case is exercised without depending on how this repo happens to
be checked out.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.integration.sibling_repo import (
    GUBBI_VERSIONS_RELATIVE,
    REQUIRE_SIBLING_ENV,
    is_versions_dir,
    iter_sibling_candidates,
    resolve_gubbi_versions_dir,
    sibling_required,
)

pytestmark = pytest.mark.unit


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _make_gubbi_checkout(root: Path, *, populated: bool = True) -> Path:
    """Create ``<root>/gubbi/gubbi/alembic/versions`` and return it."""
    versions = root / "gubbi" / Path(*GUBBI_VERSIONS_RELATIVE)
    versions.mkdir(parents=True)
    if populated:
        (versions / "20260914_0003_audit_log_app_dedup_read.py").write_text(
            "revision = '0003'\n", encoding="utf-8"
        )
    return versions


def _make_repo(root: Path, name: str) -> Path:
    """Create a minimal Git repo with one commit and return its path."""
    repo = root / name
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "mod.py").write_text("x = 1\n", encoding="utf-8")
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "tests@example.invalid", cwd=repo)
    _git("config", "user.name", "tests", cwd=repo)
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "initial", cwd=repo)
    return repo


# ---------------------------------------------------------------------------
# is_versions_dir
# ---------------------------------------------------------------------------


def test_populated_versions_directory_is_recognized(tmp_path: Path) -> None:
    versions = _make_gubbi_checkout(tmp_path)

    assert is_versions_dir(versions) is True


def test_empty_versions_directory_is_rejected(tmp_path: Path) -> None:
    """A directory left behind by a failed checkout must not satisfy the resolver."""
    versions = _make_gubbi_checkout(tmp_path, populated=False)

    assert is_versions_dir(versions) is False


def test_versions_directory_holding_only_a_package_marker_is_rejected(tmp_path: Path) -> None:
    versions = _make_gubbi_checkout(tmp_path, populated=False)
    (versions / "__init__.py").write_text("", encoding="utf-8")

    assert is_versions_dir(versions) is False


def test_missing_directory_is_rejected(tmp_path: Path) -> None:
    assert is_versions_dir(tmp_path / "nope") is False


# ---------------------------------------------------------------------------
# Resolution: main checkout, nested worktree, absent sibling
# ---------------------------------------------------------------------------


def test_resolves_sibling_from_a_main_checkout(tmp_path: Path) -> None:
    # Arrange
    versions = _make_gubbi_checkout(tmp_path)
    main = _make_repo(tmp_path, "gubbi-common")

    # Act
    resolved = resolve_gubbi_versions_dir(main / "pkg")

    # Assert
    assert resolved == versions


def test_resolves_sibling_from_a_nested_git_worktree(tmp_path: Path) -> None:
    """The worktree case the fixed parent-depth path missed.

    The worktree lives at ``<main>/.claude/worktrees/<name>``, so counting
    a fixed number of parents from a test file lands below the sibling
    rather than beside it.
    """
    # Arrange
    versions = _make_gubbi_checkout(tmp_path)
    main = _make_repo(tmp_path, "gubbi-common")
    worktree = main / ".claude" / "worktrees" / "wt-probe"
    worktree.parent.mkdir(parents=True)
    _git("worktree", "add", "-q", "-b", "wt-probe", str(worktree), cwd=main)

    # Act
    resolved = resolve_gubbi_versions_dir(worktree / "pkg")

    # Assert
    assert resolved == versions


def test_resolves_sibling_from_a_worktree_outside_the_sibling_ancestor_chain(
    tmp_path: Path,
) -> None:
    """The case ONLY the Git common-directory anchor solves.

    When the worktree is checked out somewhere unrelated -- not under the
    main repo, and with no ancestor in common with the sibling -- walking
    the working tree's own parents can never reach gubbi. The common
    directory points back at the main checkout, whose parent holds it.
    """
    # Arrange
    project = tmp_path / "project"
    project.mkdir()
    versions = _make_gubbi_checkout(project)
    main = _make_repo(project, "gubbi-common")
    elsewhere = tmp_path / "scratch" / "detached-wt"
    elsewhere.parent.mkdir(parents=True)
    _git("worktree", "add", "-q", "-b", "wt-detached", str(elsewhere), cwd=main)

    # Act
    resolved = resolve_gubbi_versions_dir(elsewhere / "pkg")

    # Assert
    assert resolved == versions


def test_worktree_outside_the_chain_is_unreachable_without_the_git_anchor(
    tmp_path: Path,
) -> None:
    """Paired control: the same tree has no candidate among working-tree ancestors.

    This is what makes the test above meaningful -- it proves the sibling
    is genuinely off the ancestor path, so resolution there can only come
    from the Git common directory.
    """
    # Arrange
    project = tmp_path / "project"
    project.mkdir()
    versions = _make_gubbi_checkout(project)
    elsewhere = tmp_path / "scratch" / "detached-wt" / "pkg"
    elsewhere.mkdir(parents=True)

    # Act: candidates derived from a plain directory, with no repo at all.
    candidates = iter_sibling_candidates(elsewhere)

    # Assert
    assert versions not in candidates
    assert resolve_gubbi_versions_dir(elsewhere) is None


def test_returns_none_when_no_sibling_checkout_exists(tmp_path: Path) -> None:
    # Arrange
    main = _make_repo(tmp_path, "gubbi-common")

    # Act
    resolved = resolve_gubbi_versions_dir(main / "pkg")

    # Assert
    assert resolved is None


def test_returns_none_when_the_sibling_versions_directory_is_empty(tmp_path: Path) -> None:
    """Paired control for the populated case: same tree shape, no revisions."""
    # Arrange
    _make_gubbi_checkout(tmp_path, populated=False)
    main = _make_repo(tmp_path, "gubbi-common")

    # Act / Assert
    assert resolve_gubbi_versions_dir(main / "pkg") is None


def test_resolves_when_the_anchor_is_itself_the_gubbi_checkout_root(tmp_path: Path) -> None:
    # Arrange
    versions = tmp_path / "gubbi" / Path(*GUBBI_VERSIONS_RELATIVE)
    versions.mkdir(parents=True)
    (versions / "20260914_0003_audit_log_app_dedup_read.py").write_text("", encoding="utf-8")

    # Act
    resolved = resolve_gubbi_versions_dir(tmp_path / "gubbi")

    # Assert
    assert resolved == versions


def test_resolution_works_outside_any_git_repository(tmp_path: Path) -> None:
    """No repo means no common dir; the working-tree ancestors still resolve."""
    # Arrange
    versions = _make_gubbi_checkout(tmp_path)
    start = tmp_path / "loose" / "deep"
    start.mkdir(parents=True)

    # Act / Assert
    assert resolve_gubbi_versions_dir(start) == versions


# ---------------------------------------------------------------------------
# Candidate ordering
# ---------------------------------------------------------------------------


def test_candidate_list_is_deterministic_and_deduplicated(tmp_path: Path) -> None:
    # Arrange
    start = tmp_path / "a" / "b"
    start.mkdir(parents=True)

    # Act
    first = iter_sibling_candidates(start)
    second = iter_sibling_candidates(start)

    # Assert
    assert first == second
    assert len(first) == len(set(first))


def test_nearest_anchor_is_tried_before_its_ancestors(tmp_path: Path) -> None:
    # Arrange
    start = tmp_path / "a" / "b"
    start.mkdir(parents=True)

    # Act
    candidates = iter_sibling_candidates(start)
    nearest = start / "gubbi" / Path(*GUBBI_VERSIONS_RELATIVE)
    ancestor = tmp_path / "gubbi" / Path(*GUBBI_VERSIONS_RELATIVE)

    # Assert
    assert candidates.index(nearest) < candidates.index(ancestor)


# ---------------------------------------------------------------------------
# Required-sibling switch
# ---------------------------------------------------------------------------


def test_sibling_is_not_required_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(REQUIRE_SIBLING_ENV, raising=False)

    assert sibling_required() is False


def test_sibling_is_required_when_the_env_var_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUIRE_SIBLING_ENV, "1")

    assert sibling_required() is True


@pytest.mark.parametrize("value", ["", "0", "true", "yes"])
def test_only_the_exact_value_one_requires_the_sibling(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(REQUIRE_SIBLING_ENV, value)

    assert sibling_required() is False
