"""Tests for tools/check_gubbi_common_purity.py (B5 Q3 lint).

Validates the AST walker by feeding it pure-source strings rather than
real files; the walker is implemented as a pure function for exactly
this reason.

Cases mirror the bundle brief:
  a. Clean stdlib-only file passes.
  b. RUNTIME deny-listed import fails (filename + import named).
  c. Same import inside ``if TYPE_CHECKING:`` passes.
  d. Same import inside the ``else:`` branch of ``if TYPE_CHECKING:``
     fails (it's a runtime fallback).
  e. Multi-name ``from X import a, b`` with deny-listed ``X`` fails.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# Repository root so we can locate the lint script.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SCRIPT_PATH = _REPO_ROOT / "tools" / "check_gubbi_common_purity.py"


# Make `tools` importable without installing it; the script is a
# stand-alone module with no package wrapper.
sys.path.insert(0, str(_REPO_ROOT))

from tools.check_gubbi_common_purity import (  # noqa: E402  -- after sys.path mutation
    DENY_LIST,
    Violation,
    parse_imports,
)


@pytest.mark.unit
def test_clean_stdlib_only_passes() -> None:
    """a. Clean file with only stdlib imports passes."""
    source = textwrap.dedent(
        """
        from __future__ import annotations
        import os
        import json
        from collections.abc import Mapping
        from typing import Any

        def f(x: int) -> int:
            return x
        """
    )
    violations = parse_imports(source, "clean.py")
    assert violations == []


@pytest.mark.unit
def test_runtime_denylist_import_fails() -> None:
    """b. RUNTIME deny-listed import fails; error names file + import."""
    source = textwrap.dedent(
        """
        from __future__ import annotations
        import fastapi
        """
    )
    violations = parse_imports(source, "bad.py")
    assert len(violations) == 1
    v = violations[0]
    assert isinstance(v, Violation)
    assert v.imported == "fastapi"
    assert v.root_module == "fastapi"
    assert v.rel_path == "bad.py"
    msg = v.message()
    assert "bad.py" in msg
    assert "fastapi" in msg


@pytest.mark.unit
def test_type_checking_block_is_exempt() -> None:
    """c. Same deny-listed import inside ``if TYPE_CHECKING:`` passes."""
    source = textwrap.dedent(
        """
        from __future__ import annotations
        from typing import TYPE_CHECKING

        if TYPE_CHECKING:
            from fastapi import FastAPI
            import starlette.types
        """
    )
    assert parse_imports(source, "ok_typing.py") == []


@pytest.mark.unit
def test_type_checking_else_branch_is_runtime() -> None:
    """d. Imports in the ``else:`` of ``if TYPE_CHECKING:`` are RUNTIME.

    The ``else:`` runs when ``TYPE_CHECKING is False`` -- which is
    always at runtime. Treating it as type-only would silently let a
    runtime fallback slip through.
    """
    source = textwrap.dedent(
        """
        from __future__ import annotations
        from typing import TYPE_CHECKING

        if TYPE_CHECKING:
            from typing import Any as Redis
        else:
            import redis as Redis
        """
    )
    violations = parse_imports(source, "fallback.py")
    assert len(violations) == 1
    assert violations[0].imported == "redis"


@pytest.mark.unit
def test_multi_name_from_import_with_denied_module_fails() -> None:
    """e. ``from fastapi import Request, Depends`` fails (any banned root)."""
    source = textwrap.dedent(
        """
        from __future__ import annotations
        from fastapi import Request, Depends
        """
    )
    violations = parse_imports(source, "multi.py")
    # One ImportFrom node => one violation (we deny at module-root level
    # so the listed names don't multiply the count).
    assert len(violations) == 1
    assert violations[0].imported == "fastapi"


# ---------------------------------------------------------------------------
# Additional coverage: extra patterns we want pinned
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_dotted_imports_collapse_to_root() -> None:
    """``starlette.types`` is treated as ``starlette`` for the deny check."""
    source = textwrap.dedent(
        """
        from __future__ import annotations
        from starlette.types import ASGIApp
        """
    )
    violations = parse_imports(source, "dotted.py")
    assert len(violations) == 1
    assert violations[0].imported == "starlette.types"
    assert violations[0].root_module == "starlette"


@pytest.mark.unit
def test_qualified_type_checking_attribute_is_recognised() -> None:
    """``if typing.TYPE_CHECKING:`` works the same as the bare name."""
    source = textwrap.dedent(
        """
        from __future__ import annotations
        import typing

        if typing.TYPE_CHECKING:
            import httpx
        """
    )
    assert parse_imports(source, "qualified.py") == []


@pytest.mark.unit
def test_non_typing_attribute_named_type_checking_is_runtime() -> None:
    """R1 fix-pass guard: only ``typing.TYPE_CHECKING`` (or bare) is exempt.

    A runtime guard like ``if some_obj.TYPE_CHECKING:`` must NOT bypass
    the lint -- ``some_obj`` may be a runtime-truthy attribute. Pre-fix
    the helper matched any ``*.TYPE_CHECKING`` attribute access; this
    test pins the tightened contract.
    """
    source = textwrap.dedent(
        """
        from __future__ import annotations

        class Sneaky:
            TYPE_CHECKING = True

        sneaky = Sneaky()
        if sneaky.TYPE_CHECKING:
            import httpx
        """
    )
    violations = parse_imports(source, "sneaky.py")
    assert len(violations) == 1
    assert violations[0].imported == "httpx"


@pytest.mark.unit
def test_import_inside_function_body_is_runtime() -> None:
    """A deferred import inside a def is still runtime when called."""
    source = textwrap.dedent(
        """
        from __future__ import annotations

        def get_client():
            import httpx
            return httpx.Client()
        """
    )
    violations = parse_imports(source, "deferred.py")
    assert len(violations) == 1
    assert violations[0].imported == "httpx"


@pytest.mark.unit
def test_relative_imports_are_never_violations() -> None:
    """Intra-package relative imports cannot be deny-listed (no module name)."""
    source = "from . import sibling\nfrom .. import other\n"
    assert parse_imports(source, "rel.py") == []


@pytest.mark.unit
def test_allow_exception_for_known_paths() -> None:
    """The hard-coded ALLOW for db/user_scoped.py exempts asyncpg there only.

    A different file importing asyncpg at runtime still fails.
    """
    # Same import statement, two different paths.
    source = "import asyncpg\n"
    # Allowed path: no violation.
    assert parse_imports(source, "db/user_scoped.py") == []
    # Other path: violation.
    other = parse_imports(source, "telemetry/something.py")
    assert len(other) == 1
    assert other[0].imported == "asyncpg"


@pytest.mark.unit
def test_deny_list_includes_expected_packages() -> None:
    """Pin the deny-list contents -- changing it is a deliberate decision."""
    expected = {
        "fastapi",
        "starlette",
        "uvicorn",
        "sqlalchemy",
        "redis",
        "asyncpg",
        "anthropic",
        "arq",
        "httpx",
        "mcp",
        "stripe",
        "pgvector",
        "bcrypt",
        # R1 fix-pass extension: cover sibling-repo runtime deps.
        # Use the IMPORT name (PyJWT installs as ``jwt``).
        "jwt",
        "cryptography",
        "psycopg",
    }
    assert set(DENY_LIST) == expected


@pytest.mark.unit
def test_cli_returns_zero_on_clean_package(tmp_path: Path) -> None:
    """End-to-end: running the script over a clean fake package exits 0."""
    pkg = tmp_path / "fake_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("import os\n")
    (pkg / "a.py").write_text("from __future__ import annotations\nfrom typing import Any\n")

    proc = subprocess.run(
        [sys.executable, str(_SCRIPT_PATH), "--package", str(pkg)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.unit
def test_cli_returns_one_on_violation(tmp_path: Path) -> None:
    """End-to-end: a deny-listed runtime import causes exit 1 + named file."""
    pkg = tmp_path / "fake_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "bad.py").write_text("import redis\n")

    proc = subprocess.run(
        [sys.executable, str(_SCRIPT_PATH), "--package", str(pkg)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "bad.py" in proc.stderr
    assert "redis" in proc.stderr
