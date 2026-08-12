"""RE-02 (v0.1.7 review) — release-archive manifest regression.

The v0.1.5 hardened archive included `.github/workflows/ci.yml`. My
v0.1.6 rebuild used `zip -x '*.git*'` which stripped every dotfile
whose name matched `*.git*` — losing `.github/`, `.gitignore`, and
`.gitattributes`. The reviewer flagged this as RE-02: a hardened
source release that omits the CI workflow the release claims to run
is not a reproducible release control.

This test refuses to pass if these files are missing from the repo
tree that a release archive should mirror. The archive-build step
itself lives outside the tree (in the release script that runs zip);
this test is the tripwire that says "if you shipped an archive that
doesn't have these paths, your archive is defective."
"""

from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).parent.parent


REQUIRED_RELEASE_PATHS = [
    # CI workflow that the release claims produces exact-candidate CI
    # evidence for RE-01. Losing this makes the exact-candidate claim
    # unverifiable.
    ".github/workflows/ci.yml",
    # Dotfiles that describe how the repo is structured for CI and
    # local checkouts. Losing these was the root cause of RE-02.
    ".gitignore",
    ".gitattributes",
    # Canonical security and threat-model documents. They also appear
    # inside the wheel under honeysnatch/data/security/ (see TM-02);
    # they must additionally be present at repo root so GitHub renders
    # them and the README links resolve.
    "SECURITY.md",
    "THREAT_MODEL.md",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "pyproject.toml",
    # Load-bearing modules whose presence a manifest check should
    # tripwire on, even though a missing __init__.py would break most
    # other tests too — this gives the release-archive check its own
    # explicit assertion.
    "honeysnatch/__init__.py",
    "honeysnatch/isolation/consent.py",
    "honeysnatch/isolation/runner.py",
    "honeysnatch/isolation/wpaspy.py",
]


@pytest.mark.parametrize("rel_path", REQUIRED_RELEASE_PATHS)
def test_release_required_path_present(rel_path):
    full = REPO_ROOT / rel_path
    assert full.exists(), (
        f"Required release-archive path missing: {rel_path!r}. If a "
        "release script omits this, the hardened archive is defective — "
        "reviewers cannot verify CI or policy from the archive alone. "
        "This mirrors the RE-02 finding from the v0.1.6 review."
    )


def test_ci_workflow_defines_python_matrix():
    """Sanity check that the workflow is the one the release claims —
    a matrix job across Python 3.10/3.11/3.12 — not an empty placeholder."""
    ci_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    body = ci_yml.read_text(encoding="utf-8")
    for anchor in ("3.10", "3.11", "3.12", "pytest"):
        assert anchor in body, (
            f".github/workflows/ci.yml is missing anchor {anchor!r} — the "
            "workflow this release claims to run does not appear to be "
            "the one currently at that path. Reviewers cannot verify "
            "the exact-candidate CI without this."
        )
