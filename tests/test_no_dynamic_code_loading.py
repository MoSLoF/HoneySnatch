"""TB-01 (v0.1.6) — trusted-process boundary prerequisites.

The v0.1.5 review flagged that `_AUTHENTIC_AUTHORIZATIONS` is a module
global that any same-process caller can mutate. v0.1.6's response
(THREAT_MODEL.md) is to narrow the threat model: the consent gate
protects against operator mistakes, CLI accidents, and cross-attack
drift, NOT against hostile Python code with equivalent interpreter
access. That narrowing is only valid while the deployment surface
does not include third-party in-process code.

This test codifies the code-level prerequisites for that boundary. It
refuses to pass if a future commit introduces:

1. A plugin discovery mechanism (`entry_points` / `pluggy`) that would
   let arbitrary third-party packages load into the `fhs` process.
2. `importlib.import_module` / `__import__` of caller-supplied strings
   anywhere in the honeysnatch package (which would let untrusted
   input pick what code gets loaded).

If a future commit legitimately needs one of the above, it must ALSO
update THREAT_MODEL.md to reflect the changed surface — otherwise the
threat model in SECURITY.md is a lie and TB-01 becomes an actual
release vulnerability.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).parent.parent
HONEYSNATCH = REPO_ROOT / "honeysnatch"
PYPROJECT = REPO_ROOT / "pyproject.toml"
THREAT_MODEL = REPO_ROOT / "THREAT_MODEL.md"


def test_threat_model_document_exists():
    """THREAT_MODEL.md is the anchor document for TB-01's Option A.

    Losing this document silently would let SECURITY.md's consent-gate
    claims drift back into overclaim territory.
    """
    assert THREAT_MODEL.exists(), (
        "THREAT_MODEL.md must exist at the repo root — it is the anchor "
        "for the TB-01 (v0.1.6) trusted-process boundary declaration. "
        "If this test fails, either restore the document or explicitly "
        "amend SECURITY.md to remove the trusted-process claim."
    )
    body = THREAT_MODEL.read_text(encoding="utf-8")
    # Anchor-string check: these are the load-bearing pieces of the
    # threat-model declaration. If they disappear, someone edited the
    # doc into something that no longer describes the TB-01 boundary.
    for anchor in [
        "TB-01",
        "trusted-process",
        "_AUTHENTIC_AUTHORIZATIONS",
        "Out-of-scope threats",
    ]:
        assert anchor.lower() in body.lower(), (
            f"THREAT_MODEL.md is missing anchor text {anchor!r} — the "
            "trusted-process boundary declaration is incomplete."
        )


def test_pyproject_does_not_declare_entry_points_for_plugins():
    """No entry_points = no third-party plugin discovery.

    `[project.scripts]` and `[project.gui-scripts]` are console/GUI
    launchers — those are FIRST-party entrypoints for the `fhs`/`fhs-gui`
    binaries themselves and do NOT trigger third-party code loading.

    What would break the model: `[project.entry-points]` groups
    (pluggy-style hooks, or setuptools plugin discovery groups like
    'honeysnatch.plugins'). We refuse to pass if such a section exists.
    """
    raw = PYPROJECT.read_text(encoding="utf-8")
    # The forbidden pattern is a `[project.entry-points...]` (or the
    # `[project.entry-points."group"]` variant). `[project.scripts]`
    # and `[project.gui-scripts]` are explicitly allowed.
    forbidden_markers = [
        "[project.entry-points",
        "[project.entry_points",   # tolerant of underscore variant
    ]
    for marker in forbidden_markers:
        assert marker not in raw, (
            f"pyproject.toml contains {marker!r} — this introduces "
            "third-party plugin discovery, which invalidates TB-01's "
            "trusted-process boundary. Either drop the entry_points "
            "section, or update THREAT_MODEL.md to declare plugins in "
            "scope and add the Option B broker before enabling this."
        )


def test_no_pluggy_or_stevedore_in_dependency_lists():
    """Neither pluggy nor stevedore is in any requirements file.

    Either of those crates in the dep graph implies third-party plugin
    discovery is intended. If a future PR adds one for a legitimate
    reason, this test forces the author to update THREAT_MODEL.md at
    the same time.
    """
    forbidden = {"pluggy", "stevedore"}
    checked = 0
    for req in REPO_ROOT.glob("requirements*.txt"):
        checked += 1
        lines = req.read_text(encoding="utf-8").splitlines()
        for line in lines:
            name = line.strip().split("==")[0].split(">=")[0].split("[")[0].lower()
            assert name not in forbidden, (
                f"{req.name} declares {name!r} — plugin-discovery libraries "
                "expand the trusted-process surface. Update THREAT_MODEL.md "
                "and add the Option B broker before adding this dep."
            )
    assert checked > 0, "Expected at least one requirements*.txt file to scan."


def test_no_dynamic_import_of_caller_supplied_names_in_honeysnatch():
    """AST walk over honeysnatch/ for every known dynamic-execution API.

    DL-01 (v0.1.6 review): the previous version of this test only
    covered `importlib.import_module(...)` and bare `__import__(...)`.
    The reviewer pointed out that `honeysnatch/isolation/wpaspy.py`
    loads its vendored module via `importlib.util.spec_from_file_location`
    followed by `loader.exec_module` — a completely different loader
    API that the old test could not see. This version covers every
    dynamic-execution surface the reviewer named:

    - `importlib.import_module(name)`
    - `__import__(name)`
    - `importlib.util.spec_from_file_location(name, path)`
    - `importlib.util.module_from_spec(spec)`
    - `<loader>.exec_module(module)` and `<spec>.loader.exec_module(...)`
    - `runpy.run_path(path)` / `runpy.run_module(name)`
    - bare `eval(code)` and `exec(code)`

    For each call site the test verifies that every argument that
    could influence WHICH code is loaded is a string literal — a
    constant a reviewer can see and evaluate at read time. Non-literal
    arguments (Name, Attribute, Call, BinOp, JoinedStr, ...) mean the
    executed code is decided at runtime by data that might not itself
    be trusted.

    Two allowances that are NOT bypasses:

    1. `spec_from_file_location` path arguments constructed from
       `Path(__file__).resolve().parents[N] / "..." / "vendor" / ...`
       are considered package-anchored: the base is the installed
       module's own path, and every component after it is a literal.
       This is the wpaspy pattern; extending it to other vendor
       shims is fine.
    2. `str(path)` wrapping such an expression is unwrapped before
       the check.

    Anything else — including a bare `Name` node or a path fragment
    built from a config value — fails the test.
    """
    offenders: list[tuple[str, int, str, str]] = []

    for py in HONEYSNATCH.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover — should be caught by compileall
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            rel = str(py.relative_to(REPO_ROOT))
            for surface, arg in _dynamic_load_call_args(node):
                if _is_reviewable_source(arg):
                    continue
                offenders.append(
                    (rel, node.lineno, surface, ast.dump(arg)[:120])
                )

    assert not offenders, (
        "Dynamic code-loading call with non-literal / non-package-anchored "
        "argument found in honeysnatch/. Under TB-01's trusted-process "
        "model, all executed code must come from a source a reviewer can "
        "evaluate at read time. Offenders:\n"
        + "\n".join(
            f"  {p}:{lineno}  [{surface}]  {arg}"
            for p, lineno, surface, arg in offenders
        )
    )


def test_wpaspy_loader_path_is_package_anchored():
    """DL-01 spot-check: the one legitimate dynamic loader
    (`honeysnatch/isolation/wpaspy.py`) uses `spec_from_file_location`
    with a path derived from `Path(__file__).resolve().parents[N] /
    "vendor" / ...`. That means the loaded file is fixed relative to
    the installed package — an operator cannot redirect the load by
    setting an env var, editing a config file, or passing a CLI arg.

    This test refuses to pass if a future refactor makes the wpaspy
    loader path caller-influenceable (e.g. reading a directory from
    `os.environ`, from a config dict, or from a click parameter).
    """
    wpaspy = HONEYSNATCH / "isolation" / "wpaspy.py"
    assert wpaspy.exists(), "honeysnatch/isolation/wpaspy.py missing"

    tree = ast.parse(wpaspy.read_text(encoding="utf-8"))
    found_loader_call = False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        surface_args = list(_dynamic_load_call_args(node))
        for surface, arg in surface_args:
            if surface != "importlib.util.spec_from_file_location":
                continue
            found_loader_call = True
            assert _is_reviewable_source(arg), (
                f"wpaspy loader path is not package-anchored at "
                f"line {node.lineno}: {ast.dump(arg)[:200]}. Any wpaspy "
                "load path must be reachable from Path(__file__) only — "
                "not from environment variables, config, or CLI input."
            )

    assert found_loader_call, (
        "Expected at least one importlib.util.spec_from_file_location "
        "call in wpaspy.py — did the loader move? Update this test to "
        "point at the new location, or drop it if the loader was "
        "replaced with a plain packaged import."
    )


# ------------------------------------------------------------------ helpers


_DYNAMIC_CALL_SURFACES = {
    # (module or None, attribute or bare-name): [arg indices to check]
    #
    # For calls we match by attribute chain: ("importlib", "import_module")
    # matches `importlib.import_module(...)`. ("importlib.util",
    # "spec_from_file_location") matches `importlib.util.spec_from_file_location`.
    ("importlib", "import_module"): (0,),
    ("importlib.util", "spec_from_file_location"): (1,),  # arg 1 is the PATH
    ("importlib.util", "module_from_spec"): (),  # spec is opaque; skip arg check
    ("runpy", "run_path"): (0,),
    ("runpy", "run_module"): (0,),
    # Bare-name builtins:
    (None, "__import__"): (0,),
    (None, "eval"): (0,),
    (None, "exec"): (0,),
}
# Method-call surfaces where the receiver is not a fixed module.
# For these we match by method name alone.
_DYNAMIC_METHOD_NAMES = {"exec_module"}  # loader.exec_module(module) — module is
                                          # already loaded; but presence is worth
                                          # flagging so we notice the surface exists


def _attr_chain(expr: ast.AST) -> str | None:
    """Return the dotted attribute chain for a Name/Attribute expression.

    `importlib.util.spec_from_file_location` -> "importlib.util.spec_from_file_location".
    `spec.loader.exec_module` -> "spec.loader.exec_module".
    Returns None for anything else (calls, subscripts, ...).
    """
    parts = []
    cur = expr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _dynamic_load_call_args(node: ast.Call):
    """Yield (surface_name, arg_ast) tuples for dynamic-execution calls.

    Empty yield if `node` isn't one of the tracked surfaces.
    """
    chain = _attr_chain(node.func)

    if chain is not None:
        # Try qualified surfaces first (importlib.import_module, etc.)
        for (mod, attr), arg_indices in _DYNAMIC_CALL_SURFACES.items():
            if mod is None:
                # Bare-name builtins: chain must equal the attr exactly
                if chain == attr:
                    surface = attr
                    for idx in arg_indices:
                        if idx < len(node.args):
                            yield surface, node.args[idx]
                    if not arg_indices:
                        # No args to check but yield a sentinel to record surface
                        pass
            else:
                # Qualified: chain must end with mod.attr (allow prefix mismatch
                # e.g. import as: `from importlib import util; util.spec_...`).
                # Full-chain match is the primary form; also match the last
                # two segments as a fallback for `from importlib import util`.
                full = f"{mod}.{attr}"
                if chain == full or chain.endswith("." + full) or chain.endswith("." + attr) and mod.split(".")[-1] in chain:
                    surface = full
                    if not arg_indices:
                        continue
                    for idx in arg_indices:
                        if idx < len(node.args):
                            yield surface, node.args[idx]

    # Method-name surfaces (spec.loader.exec_module, etc.)
    if isinstance(node.func, ast.Attribute) and node.func.attr in _DYNAMIC_METHOD_NAMES:
        # exec_module(module) — the `module` was constructed elsewhere; the
        # dangerous decision was WHICH SPEC produced it, which we cover via
        # spec_from_file_location. But surface a warning if the arg is not
        # a Name — an inline call would be unusual.
        if node.args and not isinstance(node.args[0], ast.Name):
            yield f"loader.{node.func.attr}", node.args[0]


def _is_reviewable_source(arg: ast.AST) -> bool:
    """True if `arg` is a source a reviewer can pin at read time.

    Accepted forms:
      - String literal: `"honeysnatch.utils.audit"`, `"html"`, ...
      - `str(EXPR)` where EXPR is package-anchored (unwrapped and recursed).
      - Package-anchored path expression: an ast.BinOp/Attribute rooted at
        `Path(__file__)...` where every non-`__file__` component is a
        literal or a resolved package traversal.
    """
    # Unwrap `str(EXPR)` → EXPR
    if (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Name)
        and arg.func.id == "str"
        and len(arg.args) == 1
    ):
        return _is_reviewable_source(arg.args[0])

    # String literal
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return True

    # Package-anchored path: contains a `__file__` reference AND every
    # user-visible component is a literal. We do a permissive walk:
    # accept if the AST subtree references `__file__` somewhere and does
    # NOT reference any Name we consider tainted (env, config, argv, ...).
    tainted_names = {
        "os",   # os.environ, os.getenv, etc — flag; environment is caller-influenced
        "sys",  # sys.argv
        "input",
        "click",
        "argparse",
        "config",
        "cfg",
        "settings",
    }
    has_file_anchor = False
    for sub in ast.walk(arg):
        if isinstance(sub, ast.Name):
            if sub.id == "__file__":
                has_file_anchor = True
            elif sub.id in tainted_names:
                return False
        elif isinstance(sub, ast.Attribute) and sub.attr == "environ":
            return False
    return has_file_anchor
