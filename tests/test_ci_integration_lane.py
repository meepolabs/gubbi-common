"""Contract tests for the CI test workflow.

The integration lane's staleness guards are only meaningful if the
sibling migration source is actually present and pinned. Three properties
have to hold together, and none is visible from the test code alone:

* the sibling is checked out at an IMMUTABLE revision, never a branch;
* it lands at the path the resolver looks in;
* the checkout happens BEFORE pytest runs, with the require-sibling
  switch set so absence fails the lane instead of skipping it.

These tests parse the workflow rather than grepping it, so a
reformatting, a step reorder, or a quoting change cannot make them pass
vacuously.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import pytest
import yaml

pytestmark = pytest.mark.unit

_WORKFLOW_PATH: Final[Path] = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "test.yml"
)

# The immutable gubbi revision the integration lane pins. A 40-hex commit
# id, never a branch or tag: a moving ref would let an unrelated sibling
# commit change this lane's verdict.
PINNED_GUBBI_REVISION: Final[str] = "a74ae71114d346c4118d67922e2c5e5387d9aaa8"

# Path, relative to the workspace, where the sibling is checked out. Must
# match what tests/integration/sibling_repo.py resolves.
PINNED_GUBBI_PATH: Final[str] = "gubbi"

_CHECKOUT_ACTION: Final[str] = "actions/checkout"


@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    parsed = yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    return parsed


@pytest.fixture(scope="module")
def test_job_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    job = workflow["jobs"]["test"]
    steps = job["steps"]
    assert isinstance(steps, list)
    return [step for step in steps if isinstance(step, dict)]


def _sibling_checkout_step(steps: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [
        step
        for step in steps
        if str(step.get("uses", "")).startswith(_CHECKOUT_ACTION)
        and isinstance(step.get("with"), dict)
        and step["with"].get("repository")
    ]
    assert len(matches) == 1, (
        f"expected exactly one sibling checkout step, found {len(matches)}: "
        f"{[step.get('name') for step in matches]}"
    )
    return matches[0]


def _pytest_step(steps: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [step for step in steps if "pytest" in str(step.get("run", ""))]
    assert len(matches) == 1, f"expected exactly one pytest step, found {len(matches)}"
    return matches[0]


def _step_index(steps: list[dict[str, Any]], target: dict[str, Any]) -> int:
    for index, step in enumerate(steps):
        if step is target:
            return index
    raise AssertionError("step not found in job")


# ---------------------------------------------------------------------------
# Sibling checkout: revision, path, immutability
# ---------------------------------------------------------------------------


def test_integration_lane_checks_out_the_sibling_repository(
    test_job_steps: list[dict[str, Any]],
) -> None:
    step = _sibling_checkout_step(test_job_steps)

    assert step["with"]["repository"] == "meepolabs/gubbi"


def test_sibling_checkout_pins_the_immutable_revision(
    test_job_steps: list[dict[str, Any]],
) -> None:
    step = _sibling_checkout_step(test_job_steps)

    assert step["with"]["ref"] == PINNED_GUBBI_REVISION


def test_sibling_checkout_ref_is_a_full_commit_id_not_a_moving_ref(
    test_job_steps: list[dict[str, Any]],
) -> None:
    """A branch name here would let an unrelated sibling commit flip this lane."""
    # Arrange
    step = _sibling_checkout_step(test_job_steps)
    ref = str(step["with"]["ref"])

    # Assert
    assert len(ref) == 40, f"ref {ref!r} is not a full 40-character commit id"
    assert all(char in "0123456789abcdef" for char in ref), f"ref {ref!r} is not lowercase hex"
    for moving in ("develop", "main", "master", "HEAD", "latest"):
        assert moving not in ref


def test_sibling_checkout_lands_at_the_path_the_resolver_searches(
    test_job_steps: list[dict[str, Any]],
) -> None:
    # Arrange
    from tests.integration.sibling_repo import GUBBI_VERSIONS_RELATIVE, iter_sibling_candidates

    step = _sibling_checkout_step(test_job_steps)
    checkout_path = str(step["with"]["path"])

    # Act: the workspace root is the anchor in CI, and the checkout lands
    # one level below it.
    workspace = Path("/workspace")
    expected = workspace / checkout_path / Path(*GUBBI_VERSIONS_RELATIVE)

    # Assert
    assert checkout_path == PINNED_GUBBI_PATH
    assert expected in iter_sibling_candidates(workspace)


def test_sibling_checkout_does_not_persist_credentials(
    test_job_steps: list[dict[str, Any]],
) -> None:
    step = _sibling_checkout_step(test_job_steps)

    assert step["with"]["persist-credentials"] is False


# ---------------------------------------------------------------------------
# Ordering and the require-sibling switch
# ---------------------------------------------------------------------------


def test_sibling_checkout_runs_before_pytest(test_job_steps: list[dict[str, Any]]) -> None:
    checkout = _sibling_checkout_step(test_job_steps)
    run_tests = _pytest_step(test_job_steps)

    assert _step_index(test_job_steps, checkout) < _step_index(test_job_steps, run_tests)


def test_pytest_step_requires_the_sibling_rather_than_skipping(
    test_job_steps: list[dict[str, Any]],
) -> None:
    """Without this, a broken checkout step would leave the guards skipped and green."""
    # Arrange
    from tests.integration.sibling_repo import REQUIRE_SIBLING_ENV

    step = _pytest_step(test_job_steps)
    env = step["env"]

    # Assert
    assert env[REQUIRE_SIBLING_ENV] == "1"


def test_pytest_step_enables_the_integration_lane(test_job_steps: list[dict[str, Any]]) -> None:
    step = _pytest_step(test_job_steps)

    assert step["env"]["INTEGRATION"] == "1"


def test_repo_checkout_precedes_the_sibling_checkout(
    test_job_steps: list[dict[str, Any]],
) -> None:
    """The sibling must land inside this repo's workspace, so its checkout is second."""
    # Arrange
    own_checkouts = [
        step
        for step in test_job_steps
        if str(step.get("uses", "")).startswith(_CHECKOUT_ACTION)
        and not (isinstance(step.get("with"), dict) and step["with"].get("repository"))
    ]
    sibling = _sibling_checkout_step(test_job_steps)

    # Assert
    assert len(own_checkouts) == 1
    assert _step_index(test_job_steps, own_checkouts[0]) < _step_index(test_job_steps, sibling)


def test_every_action_in_the_test_job_is_pinned_by_commit_id(
    test_job_steps: list[dict[str, Any]],
) -> None:
    for step in test_job_steps:
        uses = step.get("uses")
        if uses is None:
            continue
        _, _, ref = str(uses).partition("@")
        assert len(ref) == 40, f"action {uses!r} is not pinned to a commit id"
