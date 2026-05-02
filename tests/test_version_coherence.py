"""Pre-tag-push CI gate: pyproject.toml, ``__version__``, and CHANGELOG agree.

If this test fails, do NOT push a release tag. Either bump all three or
revert. The discrepancy that originally motivated this guard: v0.4.0 was
tagged with ``__version__ = "0.3.0"`` and no 0.4.0 CHANGELOG entry, which
made consumers' install-time version checks lie.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import pytest

import gubbi_common

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_CHANGELOG = _REPO_ROOT / "CHANGELOG.md"


def _pyproject_version() -> str:
    with _PYPROJECT.open("rb") as f:
        data = tomllib.load(f)
    return str(data["tool"]["poetry"]["version"])


def _changelog_top_version() -> str:
    """Return the X.Y.Z from the first ``## X.Y.Z`` heading in CHANGELOG.md."""
    pattern = re.compile(r"^##\s+(\d+\.\d+\.\d+)\b")
    for line in _CHANGELOG.read_text(encoding="utf-8").splitlines():
        m = pattern.match(line)
        if m:
            return m.group(1)
    raise AssertionError("no '## X.Y.Z' heading found in CHANGELOG.md")


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib requires py311+")
@pytest.mark.unit
def test_pyproject_init_changelog_versions_agree() -> None:
    pyproject = _pyproject_version()
    pkg = gubbi_common.__version__
    changelog = _changelog_top_version()
    assert pyproject == pkg == changelog, (
        f"version drift -- pyproject.toml={pyproject!r} "
        f"__version__={pkg!r} CHANGELOG={changelog!r}"
    )
