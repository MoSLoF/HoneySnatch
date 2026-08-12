"""Locate the security policy and threat-model docs from an installed wheel.

TM-02 (v0.1.7 review): the v0.1.5/v0.1.6 archives shipped SECURITY.md
and THREAT_MODEL.md at repo root, which meant a `pip install honeysnatch`
operator never got them. This module wires up
`honeysnatch/data/security/*.md` (packaged via `[tool.setuptools.package-
data]`) so `fhs help security` and equivalent runtime helpers can point
operators at the local copies of the controlling documents.

The canonical source of truth remains the repo-root copies. A parity
test (`tests/test_security_docs_in_wheel.py`) enforces byte-identity.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Iterator


_DOC_NAMES = ("SECURITY.md", "THREAT_MODEL.md")


def security_docs_dir() -> Path:
    """Return the filesystem directory that contains the shipped
    security documents.

    Uses `importlib.resources.files` under the hood, which returns a
    real filesystem path when the package is unpacked (the honeysnatch
    wheel is currently a pure-Python wheel installed to site-packages —
    the files are real).
    """
    return Path(str(resources.files("honeysnatch.data.security")))


def iter_security_docs() -> Iterator[tuple[str, Path]]:
    """Yield (name, path) for each shipped security document."""
    root = security_docs_dir()
    for name in _DOC_NAMES:
        p = root / name
        if p.exists():
            yield name, p


def read_threat_model() -> str:
    """Return THREAT_MODEL.md contents from the installed wheel."""
    return (security_docs_dir() / "THREAT_MODEL.md").read_text(encoding="utf-8")


def read_security_policy() -> str:
    """Return SECURITY.md contents from the installed wheel."""
    return (security_docs_dir() / "SECURITY.md").read_text(encoding="utf-8")
