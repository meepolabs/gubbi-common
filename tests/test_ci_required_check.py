"""Contract tests for the `required` aggregator job in the CI test workflow.

`required` is the only check the branch rule names, so a lane gates
merges only if `required` lists it in `needs`. A job added to the
workflow but not to `needs` would run, could fail, and still let the
change through. These tests parse the workflow so the job set and the
`needs` list are compared directly rather than against a hand-kept copy.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Final

import pytest
import yaml

pytestmark = pytest.mark.unit

_WORKFLOWS_DIR: Final[Path] = Path(__file__).resolve().parents[1] / ".github" / "workflows"
_WORKFLOW_PATH: Final[Path] = _WORKFLOWS_DIR / "test.yml"

_AGGREGATOR_JOB: Final[str] = "required"
_VERDICT_STEP: Final[str] = "every required job succeeded"
_SECRET_SCAN_JOB: Final[str] = "secret-scan"

# Workflows that must never gate merges: the downstream check reads
# mutable downstream branches, and dependency findings are cleared by
# update PRs rather than by blocking unrelated work.
_ADVISORY_WORKFLOWS: Final[frozenset[str]] = frozenset(
    {"cross-repo-validate.yml", "dependency-scan.yml"}
)


@pytest.fixture(scope="module")
def jobs() -> dict[str, Any]:
    parsed = yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    parsed_jobs = parsed["jobs"]
    assert isinstance(parsed_jobs, dict)
    return parsed_jobs


@pytest.fixture(scope="module")
def aggregator(jobs: dict[str, Any]) -> dict[str, Any]:
    job = jobs[_AGGREGATOR_JOB]
    assert isinstance(job, dict)
    return job


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def test_required_needs_every_other_job(jobs: dict[str, Any], aggregator: dict[str, Any]) -> None:
    """A job left out of `needs` would not gate merges at all."""
    # Arrange
    lanes = set(jobs) - {_AGGREGATOR_JOB}

    # Act
    needs = _needs(aggregator)

    # Assert
    assert len(needs) == len(set(needs)), f"duplicate entries in needs: {needs}"
    assert set(needs) == lanes


def test_required_runs_even_when_a_lane_fails(aggregator: dict[str, Any]) -> None:
    """Without always(), a failed lane skips `required`, and a skipped check can read as passing."""
    assert aggregator["if"] == "${{ always() }}"


def test_required_reports_under_its_own_name(aggregator: dict[str, Any]) -> None:
    assert aggregator["name"] == _AGGREGATOR_JOB


def test_secret_scan_is_called_as_a_required_lane(
    jobs: dict[str, Any], aggregator: dict[str, Any]
) -> None:
    # Arrange
    job = jobs[_SECRET_SCAN_JOB]

    # Act
    needs = _needs(aggregator)

    # Assert
    assert job["uses"] == "./.github/workflows/gitleaks.yml"
    assert job["name"] == "secret scan"
    assert _SECRET_SCAN_JOB in needs


def test_no_advisory_workflow_is_called(jobs: dict[str, Any]) -> None:
    for name, job in jobs.items():
        uses = str(job.get("uses", ""))
        assert Path(uses).name not in _ADVISORY_WORKFLOWS, f"job {name!r} calls advisory {uses!r}"


def test_secret_scan_workflow_is_callable_and_keeps_its_push_trigger() -> None:
    """Push scans must not depend on the caller: a newer push cancels the caller's run."""
    # Arrange
    parsed = yaml.safe_load((_WORKFLOWS_DIR / "gitleaks.yml").read_text(encoding="utf-8"))

    # Act: PyYAML reads the bare `on` key as boolean True.
    triggers = parsed[True]

    # Assert
    assert "workflow_call" in triggers
    assert "push" in triggers
    assert "pull_request" not in triggers, "pull requests are scanned through the caller"


def test_secret_scan_push_runs_never_share_a_concurrency_group() -> None:
    """A ref-keyed group lets a newer push displace the pending scan of an earlier one."""
    # Arrange
    parsed = yaml.safe_load((_WORKFLOWS_DIR / "gitleaks.yml").read_text(encoding="utf-8"))

    # Act
    concurrency = parsed["concurrency"]

    # Assert
    assert concurrency["group"] == (
        "${{ github.workflow }}-${{ github.event_name }}-"
        "${{ github.event_name == 'push' && github.sha || github.ref }}"
    )
    assert concurrency["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"


def test_pull_requests_into_every_branch_run_the_workflow() -> None:
    """The secret scan reaches pull requests only through this workflow."""
    # Arrange
    parsed = yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))

    # Act: PyYAML reads the bare `on` key as boolean True.
    pull_request = parsed[True]["pull_request"]

    # Assert
    assert not pull_request, f"pull_request trigger is filtered: {pull_request!r}"


# ---------------------------------------------------------------------------
# The verdict step, executed
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def verdict_script(aggregator: dict[str, Any]) -> str:
    steps = [step for step in aggregator["steps"] if step.get("name") == _VERDICT_STEP]
    assert len(steps) == 1
    return str(steps[0]["run"])


@pytest.mark.skipif(shutil.which("bash") is None, reason="the verdict step is a bash script")
@pytest.mark.parametrize(
    ("results", "expected_exit"),
    [
        pytest.param('["success","success","success"]', 0, id="all-success"),
        pytest.param('["success","failure","success"]', 1, id="failure"),
        pytest.param('["success","cancelled","success"]', 1, id="cancelled"),
        pytest.param('["success","skipped","success"]', 1, id="skipped"),
        pytest.param("[]", 1, id="no-results"),
    ],
)
def test_verdict_step_passes_only_when_every_lane_succeeded(
    verdict_script: str, results: str, expected_exit: int
) -> None:
    # Arrange
    env = {**os.environ, "RESULTS": results}

    # Act
    result = subprocess.run(
        ["bash", "-c", verdict_script], env=env, capture_output=True, text=True, check=False
    )

    # Assert
    assert result.returncode == expected_exit, result.stderr
