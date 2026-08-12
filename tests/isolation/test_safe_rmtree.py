"""Regression tests for _safe_rmtree containment (review finding HS-01).

The reviewer's Critical: prior denylist implementation was defeated by
`../../../etc` — os.path.abspath normalized it to `/etc`, which is 4+
chars and not in the small denylist, so `shutil.rmtree("/etc")` would
fire. These tests run unprivileged in a tmpdir and assert the guard
refuses every class of traversal and symlink attack, using a mocked
allowlist so we can prove the containment property without touching
real /run paths.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from honeysnatch.isolation import daemon as daemon_mod
from honeysnatch.isolation.daemon import _is_allowed_ctrl_path, _safe_rmtree


@pytest.fixture
def sandboxed_root(tmp_path, monkeypatch):
    """Point the allowlist at a tmpdir root so we can create paths
    'inside' it and assert the guard's behaviour without touching /run."""
    root = tmp_path / "run" / "wpa_supplicant"
    root.mkdir(parents=True)
    monkeypatch.setattr(
        daemon_mod, "_ALLOWED_CTRL_ROOTS", frozenset({str(root)})
    )
    return root


class TestAllowedCases:
    def test_direct_child_ok(self, sandboxed_root):
        good = sandboxed_root / "wlan0"
        good.mkdir()
        (good / "some-socket").touch()
        assert _is_allowed_ctrl_path(str(good)) is True
        _safe_rmtree(str(good))
        assert not good.exists()

    def test_missing_but_conformant_path_is_noop(self, sandboxed_root):
        missing = sandboxed_root / "not-yet-created"
        assert _is_allowed_ctrl_path(str(missing)) is True
        _safe_rmtree(str(missing))  # must not raise


class TestReviewersExactCriticalProbe:
    """The exact HS-01 reproducer. `../../../etc` MUST be refused now."""

    def test_traversal_to_etc_refused(self, sandboxed_root):
        # A hostile interface value like `../../../etc` gets concatenated
        # under the allowlisted root. Pre-remediation, this normalized to
        # /etc and passed the denylist. Post-remediation, the `..` segment
        # is refused up-front.
        malicious = str(sandboxed_root / ".." / ".." / ".." / "etc")
        assert _is_allowed_ctrl_path(malicious) is False
        # And _safe_rmtree of the same value must be a no-op.
        _safe_rmtree(malicious)
        assert Path("/etc").exists(), \
            "if this fails you have bigger problems than a failing test"

    def test_traversal_to_tmp_refused(self, sandboxed_root):
        malicious = str(sandboxed_root / ".." / ".." / ".." / "tmp")
        assert _is_allowed_ctrl_path(malicious) is False


class TestTraversalVariants:
    @pytest.mark.parametrize("bad", [
        "",                            # empty
        "/",                           # root
        "/etc",                        # not in allowlist
        "/tmp",                        # not in allowlist
        "/run/hostapd/../../etc",      # nested traversal
        "wlan0/../../etc/shadow",      # relative traversal
        "///etc",                      # slash normalization
        "\\..\\..\\etc",               # backslash separators
        "some\x00nul",                 # NUL byte
    ])
    def test_all_variants_refused(self, sandboxed_root, bad):
        assert _is_allowed_ctrl_path(bad) is False, \
            f"HS-01 regression: guard accepted {bad!r}"
        _safe_rmtree(bad)  # must be a no-op, not a crash

    def test_bare_root_refused(self, sandboxed_root):
        assert _is_allowed_ctrl_path(str(sandboxed_root)) is False


class TestSymlinkRefusal:
    def test_leaf_symlink_pointing_at_etc_refused(self, sandboxed_root, tmp_path):
        """If someone plants a symlink at the leaf that points at /etc,
        realpath would follow it. We must refuse before that happens."""
        victim = tmp_path / "victim-dir"
        victim.mkdir()
        (victim / "important").write_text("keep me")

        malicious_link = sandboxed_root / "wlan0"
        os.symlink(str(victim), str(malicious_link))

        assert _is_allowed_ctrl_path(str(malicious_link)) is False
        _safe_rmtree(str(malicious_link))
        # Victim dir still intact.
        assert (victim / "important").read_text() == "keep me"

    def test_parent_symlink_refused(self, sandboxed_root, tmp_path, monkeypatch):
        """Attacker replaces the parent (the allowlisted root itself)
        with a symlink to their own dir. Even though realpath would then
        succeed, we refuse because the parent-on-disk is a symlink."""
        victim = tmp_path / "victim2"; victim.mkdir()
        (victim / "file").touch()

        # Replace the sandboxed root with a symlink.
        # Move it aside first (can't unlink a non-empty dir on all FSs).
        real_root = sandboxed_root
        aside = tmp_path / "moved-real-root"
        real_root.rename(aside)
        os.symlink(str(victim), str(real_root))

        # Point the allowlist at the *symlinked* root path — this is
        # what an attacker's parent-swap would produce.
        monkeypatch.setattr(
            daemon_mod, "_ALLOWED_CTRL_ROOTS", frozenset({str(real_root)})
        )

        target = str(real_root) + "/file"
        # Realpath resolves through the symlink → still under victim,
        # which is what we're trying to prevent.
        assert _is_allowed_ctrl_path(target) is False
        _safe_rmtree(target)
        assert (victim / "file").exists()


class TestNonStringInput:
    @pytest.mark.parametrize("bad", [None, 0, [], {}, object()])
    def test_non_string_refused(self, bad):
        assert _is_allowed_ctrl_path(bad) is False  # type: ignore[arg-type]
        _safe_rmtree(bad)  # type: ignore[arg-type]


class TestOriginalReviewerProbeIsClosed:
    """One dedicated test named after the HS-01 reproducer so a
    regression is immediately obvious in CI output."""

    def test_reviewer_hs01_probe(self, sandboxed_root):
        for probe in (
            str(sandboxed_root / ".." / ".." / ".." / "etc"),
            str(sandboxed_root / ".." / ".." / ".." / "tmp"),
            str(sandboxed_root / ".." / ".." / ".." / "var" / "log"),
        ):
            assert _is_allowed_ctrl_path(probe) is False, \
                f"HS-01 REGRESSION — reviewer's Critical probe accepted: {probe!r}"
