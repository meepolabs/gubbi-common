"""Contract tests for the paths the CI lint job checks.

A directory missing from a lint command is never linted, and nothing
else reports that it was skipped. These tests parse the workflow and
read each command's path arguments so a dropped path turns red.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Final

import pytest
import yaml

pytestmark = pytest.mark.unit

_WORKFLOW_PATH: Final[Path] = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "test.yml"
)

_LINT_JOB: Final[str] = "lint"
_LINTED_PATHS: Final[tuple[str, ...]] = ("gubbi_common/", "tools/")
_LINT_STEPS: Final[tuple[str, ...]] = ("ruff check", "ruff format --check", "mypy")


@pytest.fixture(scope="module")
def lint_steps() -> dict[str, dict[str, Any]]:
    parsed = yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    steps = parsed["jobs"][_LINT_JOB]["steps"]
    assert isinstance(steps, list)
    return {step["name"]: step for step in steps if isinstance(step, dict) and "name" in step}


@pytest.mark.parametrize("step_name", _LINT_STEPS)
@pytest.mark.parametrize("path", _LINTED_PATHS)
def test_lint_step_checks_path(
    lint_steps: dict[str, dict[str, Any]], step_name: str, path: str
) -> None:
    # Arrange
    step = lint_steps[step_name]

    # Act
    argv = shlex.split(step["run"])

    # Assert
    assert path in argv, f"{step_name!r} does not check {path}: {step['run']!r}"
