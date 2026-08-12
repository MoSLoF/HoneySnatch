"""DOC-02 (v0.1.7 review) — reject stale version references in the
load-bearing sections of THREAT_MODEL.md.

The v0.1.7 reviewer caught that deployment prerequisite #1 said
"HoneySnatch v0.1.6 does not define any plugin discovery mechanism"
while the candidate was v0.1.7 — a documentation drift with no
security impact but poor aging. The fix is to keep the prerequisite
version-neutral ("this release") so a patch bump doesn't invalidate
the document.

This test enforces the rule: the deployment-prerequisites section of
THREAT_MODEL.md must not name a specific `vX.Y.Z` release. The change
log at the bottom of the document IS allowed to name versions —
that's what change logs are for.
"""

from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
THREAT_MODEL = REPO_ROOT / "THREAT_MODEL.md"

# Match `v` optionally followed by a digit-dot-digit-dot-digit release.
# The `\b` on both sides keeps it from matching mid-word.
VERSION_RE = re.compile(r"\bv\d+\.\d+\.\d+\b")

# Section boundaries: everything from "Deployment prerequisites" up to
# the next "## " heading is scrutinized. The Change log section is
# explicitly exempt because a change log HAS to name versions.
PREREQ_START_RE = re.compile(
    r"^## Deployment prerequisites for the trusted-process model\s*$",
    re.MULTILINE,
)


def test_deployment_prerequisites_do_not_pin_a_version():
    """No `vX.Y.Z` string in the deployment-prerequisites section."""
    body = THREAT_MODEL.read_text(encoding="utf-8")

    start_match = PREREQ_START_RE.search(body)
    assert start_match is not None, (
        "THREAT_MODEL.md is missing the 'Deployment prerequisites for the "
        "trusted-process model' section — someone renamed or removed the "
        "load-bearing section this test scrutinizes. Restore the section, "
        "or update this test to point at the new heading."
    )

    section_start = start_match.end()
    # Find the next `## ` heading to bound the section.
    next_heading = re.search(r"^## ", body[section_start:], re.MULTILINE)
    section_end = section_start + next_heading.start() if next_heading else len(body)
    section_text = body[section_start:section_end]

    offenders = VERSION_RE.findall(section_text)
    assert not offenders, (
        f"THREAT_MODEL.md deployment-prerequisites section names specific "
        f"version(s) {sorted(set(offenders))!r}. Use 'this release' or "
        "'the current release' instead — patch bumps must not invalidate "
        "prerequisite wording. (Change log section at the bottom is "
        "exempt and IS allowed to name versions.)"
    )


def test_change_log_still_names_current_version():
    """Sanity check: the change log at the bottom DOES name the
    latest version. If it doesn't, someone forgot to update it after
    a version bump."""
    from honeysnatch import __version__ as pkg_version  # noqa: PLC0415
    body = THREAT_MODEL.read_text(encoding="utf-8")
    # Find the "Change log" section
    change_log_match = re.search(r"^## Change log\s*$", body, re.MULTILINE)
    assert change_log_match is not None, (
        "THREAT_MODEL.md is missing its Change log section."
    )
    tail = body[change_log_match.end():]
    assert f"v{pkg_version}" in tail, (
        f"THREAT_MODEL.md Change log does not name the current release "
        f"v{pkg_version}. Add an entry so a future reader can trace which "
        "release each prose change belongs to."
    )
