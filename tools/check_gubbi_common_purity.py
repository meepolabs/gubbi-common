"""Lint gubbi-common for runtime imports of framework packages (B5 Q3).

gubbi-common is the cross-repo contract layer between gubbi (the MCP
server) and gubbi-cloud (the gateway). Runtime coupling to a web
framework defeats the point: gubbi-common modules end up dragging
``starlette`` / ``fastapi`` / ``redis`` into every consumer just to
import a contract. This lint walks every ``.py`` file under
``gubbi_common/`` and FAILS CI on any RUNTIME import from a deny-list of
framework packages.

Rules
-----
1. ``import X`` and ``from X import ...`` at the module top level (or
   inside any ``if``/``try``/``else`` block whose condition is NOT
   ``TYPE_CHECKING``) count as RUNTIME imports.
2. Imports inside an ``if TYPE_CHECKING:`` block are TYPE-ONLY and
   exempt -- the type-hints surface stays expressive without runtime
   coupling. The ``else:`` branch of such a block is RUNTIME (it runs
   when ``TYPE_CHECKING`` is False, which is true at runtime); imports
   there are NOT exempt.
3. Multi-name imports like ``from fastapi import Request, Depends`` fail
   if any one of the listed names comes from a deny-listed module.
   (We deny-list at module-root granularity, so the names don't matter
   -- the source module being deny-listed is the failure trigger.)
4. The deny-list checks the IMPORTED MODULE'S ROOT segment. So
   ``starlette.types`` is treated as ``starlette``; ``opentelemetry.trace``
   is treated as ``opentelemetry``.

Exit 0 on clean, exit 1 on any violation.

Run::

    python tools/check_gubbi_common_purity.py

Pure functions (``find_violations``, ``parse_imports``) are exposed for
testing; the ``__main__`` block is the CLI entry.
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Deny-list -- root module names whose runtime import we forbid in
# gubbi-common. Adding a new entry to this list is a one-line change.
# ---------------------------------------------------------------------------
DENY_LIST: frozenset[str] = frozenset(
    {
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
    }
)

# ---------------------------------------------------------------------------
# ALLOW exceptions -- explicit per-module justifications for runtime
# imports of deny-listed packages. Each entry MUST carry a comment
# explaining WHY the runtime import is unavoidable. Default to "no
# exceptions"; add only after exhausting the TYPE_CHECKING and "drop the
# dependency" options. Re-evaluate on every gubbi-common version bump.
#
# Format: { "<relative path under gubbi_common/>": frozenset({"<root_pkg>"}) }
# ---------------------------------------------------------------------------
ALLOW: dict[str, frozenset[str]] = {
    # asyncpg is genuinely required at runtime for the per-user RLS
    # connection helpers: catches asyncpg.exceptions.UndefinedObjectError,
    # passes asyncpg.Pool / asyncpg.Connection through the public
    # signature of user_scoped_connection, and calls conn.terminate().
    # Declared as an OPTIONAL extra in pyproject.toml ([db]) so consumers
    # that don't use the DB helpers don't pull asyncpg. Moving the
    # functionality out would require a separate gubbi-pg package; that's
    # not the right tradeoff at gubbi-common's current size.
    "db/user_scoped.py": frozenset({"asyncpg"}),
}


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Violation:
    """A single runtime-deny-list import."""

    rel_path: str
    line: int
    imported: str
    root_module: str

    def message(self) -> str:
        return (
            f"{self.rel_path}:{self.line} -- runtime import of {self.imported!r} "
            f"is denied (root={self.root_module!r}). "
            "Move under `if TYPE_CHECKING:`, drop it, or add an explicit "
            "ALLOW exception with a justification comment."
        )


# ---------------------------------------------------------------------------
# AST walking
# ---------------------------------------------------------------------------


def _root_module(name: str) -> str:
    """Return the root segment of a dotted import path.

    ``starlette.types`` -> ``starlette``;  ``redis`` -> ``redis``;
    ``""`` -> ``""`` (relative imports use this).
    """
    return name.split(".", 1)[0] if name else ""


def _is_type_checking_test(test: ast.expr) -> bool:
    """Return True if ``test`` is the ``TYPE_CHECKING`` boolean expression.

    Recognises both forms used in practice::

        if TYPE_CHECKING:           # bare name (most common)
        if typing.TYPE_CHECKING:    # qualified attribute access
    """
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def parse_imports(source: str, rel_path: str) -> list[Violation]:
    """Parse *source* and return runtime-imports that violate the deny-list.

    The walker tracks whether the current node is inside an
    ``if TYPE_CHECKING:`` BODY (type-only, exempt) or inside the
    fallback ``else:`` branch (runtime, NOT exempt -- this catches the
    common ``if TYPE_CHECKING: import X as Foo \n else: Foo = object``
    pattern that intentionally provides a runtime fallback).

    Imports inside ``try``/``except`` blocks count as runtime: a
    deny-listed package wrapped in a ``try ImportError`` is still
    runtime-coupled when the package is installed.
    """
    tree = ast.parse(source, filename=rel_path)
    violations: list[Violation] = []
    allowed_for_path = ALLOW.get(rel_path, frozenset())

    def _emit_for(line: int, imported: str) -> None:
        root = _root_module(imported)
        if root in DENY_LIST and root not in allowed_for_path:
            violations.append(
                Violation(
                    rel_path=rel_path,
                    line=line,
                    imported=imported,
                    root_module=root,
                )
            )

    def _walk(node: ast.AST, *, type_only: bool) -> None:
        # Recurse with TYPE_CHECKING-aware branching.
        if isinstance(node, ast.If) and _is_type_checking_test(node.test):
            for body_stmt in node.body:
                _walk(body_stmt, type_only=True)
            for else_stmt in node.orelse:
                # The else: branch is the RUNTIME fallback.
                _walk(else_stmt, type_only=False)
            return

        if isinstance(node, ast.Import):
            if not type_only:
                for alias in node.names:
                    _emit_for(node.lineno, alias.name)
            return

        if isinstance(node, ast.ImportFrom):
            # Relative imports (level > 0) cannot be from third-party
            # packages, so they're never deny-listed.
            if not type_only and node.level == 0 and node.module:
                _emit_for(node.lineno, node.module)
            return

        # Recurse into all generic children (function bodies, class
        # bodies, try/except blocks, etc.) so a buried runtime import
        # still gets caught.
        for descendant in ast.iter_child_nodes(node):
            _walk(descendant, type_only=type_only)

    for top in tree.body:
        _walk(top, type_only=False)

    return violations


# ---------------------------------------------------------------------------
# Filesystem walk
# ---------------------------------------------------------------------------


def find_violations(package_root: Path) -> list[Violation]:
    """Walk ``package_root`` and return all deny-list violations.

    ``package_root`` is the path to ``gubbi_common/`` (the package
    directory, not the repo root).
    """
    violations: list[Violation] = []
    for py_file in sorted(package_root.rglob("*.py")):
        if py_file.name == "__pycache__":
            continue
        rel = py_file.relative_to(package_root).as_posix()
        try:
            source = py_file.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover -- filesystem error
            sys.stderr.write(f"WARNING: failed to read {rel}: {exc}\n")
            continue
        try:
            violations.extend(parse_imports(source, rel))
        except SyntaxError as exc:
            sys.stderr.write(f"WARNING: failed to parse {rel}: {exc}\n")
            continue
    return violations


def _out(msg: str, file: Any = sys.stdout) -> None:
    file.write(msg + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail CI when gubbi-common imports a deny-listed framework "
            "package at runtime (B5 Q3=A+C). Imports inside "
            "`if TYPE_CHECKING:` are exempt."
        )
    )
    parser.add_argument(
        "--package",
        default=str(Path(__file__).resolve().parent.parent / "gubbi_common"),
        help="Path to the gubbi_common package directory.",
    )
    args = parser.parse_args(argv)

    pkg_root = Path(args.package).resolve()
    if not pkg_root.is_dir():
        _out(f"ERROR: package path is not a directory: {pkg_root}", file=sys.stderr)
        return 2

    violations = find_violations(pkg_root)
    if not violations:
        _out(f"OK: gubbi-common purity check passed ({pkg_root})")
        return 0

    _out("FAIL: gubbi-common purity violations:", file=sys.stderr)
    for v in violations:
        _out(f"  {v.message()}", file=sys.stderr)
    _out(f"\n{len(violations)} violation(s).", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
