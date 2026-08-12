"""TM-02 (v0.1.7 review) — the shipped security docs must stay in sync
with the repo-root canonical copies, and an installed wheel must be
able to find them at runtime.

Reviewer's specific concern: v0.1.5 / v0.1.6 shipped SECURITY.md and
THREAT_MODEL.md at repo root only, so a `pip install honeysnatch`
operator never received them. This test enforces:

1. Byte-parity between the repo-root docs and the packaged copies
   under `honeysnatch/data/security/`.
2. That `honeysnatch.security_docs.security_docs_dir()` resolves to
   a real filesystem path containing both files (regardless of
   whether the tree is installed as a wheel or run in-place).
3. That both `read_security_policy()` and `read_threat_model()`
   return the expected leading headers (defense against a build that
   accidentally copies an empty file into the package).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from honeysnatch import security_docs


REPO_ROOT = Path(__file__).parent.parent
CANONICAL_SECURITY = REPO_ROOT / "SECURITY.md"
CANONICAL_THREAT = REPO_ROOT / "THREAT_MODEL.md"


def test_packaged_security_md_matches_root():
    packaged = security_docs.security_docs_dir() / "SECURITY.md"
    assert packaged.exists(), (
        "SECURITY.md missing from honeysnatch/data/security/. TM-02: the "
        "security policy must be shipped inside the wheel — canonical "
        "copy lives at repo root, packaged copy must exist too."
    )
    assert packaged.read_bytes() == CANONICAL_SECURITY.read_bytes(), (
        "Packaged SECURITY.md drift from repo-root copy. Re-run the "
        "sync step (see honeysnatch/data/security/__init__.py) so an "
        "installed wheel reflects the release-time policy."
    )


def test_packaged_threat_model_md_matches_root():
    packaged = security_docs.security_docs_dir() / "THREAT_MODEL.md"
    assert packaged.exists(), (
        "THREAT_MODEL.md missing from honeysnatch/data/security/. TM-02: "
        "operators must receive the controlling boundary statement at "
        "install time."
    )
    assert packaged.read_bytes() == CANONICAL_THREAT.read_bytes(), (
        "Packaged THREAT_MODEL.md drift from repo-root copy."
    )


def test_read_helpers_return_expected_headers():
    """Defense against a build that ships empty stubs."""
    sec = security_docs.read_security_policy()
    assert sec.startswith("# Security Policy"), (
        "SECURITY.md loaded from packaged location is missing its header."
    )
    tm = security_docs.read_threat_model()
    assert tm.startswith("# HoneySnatch Threat Model"), (
        "THREAT_MODEL.md loaded from packaged location is missing its header."
    )


def test_iter_security_docs_yields_both():
    names = {name for name, _ in security_docs.iter_security_docs()}
    assert names == {"SECURITY.md", "THREAT_MODEL.md"}, (
        f"Expected iter_security_docs to yield both docs; got {names!r}"
    )
