"""Packaging tests — the installed wheel must be a working install.

Review finding HS-05: the pre-remediation package_data configuration
included only `honeysnatch*`, leaving `data/isolation/` and the vendored
hostap tree outside the wheel. A `pip install honeysnatch` produced
commands that couldn't find their own config files.

These tests exercise the packaged resource paths so a regression to the
`honeysnatch*`-only inclusion is caught in CI without needing to
actually build a wheel and reinstall.
"""

from __future__ import annotations

import importlib.resources as res
from pathlib import Path

import pytest


class TestDataAssetsAreInsidePackage:
    """The data assets that runtime code loads MUST live under the
    honeysnatch package, not at repo root."""

    def test_isolation_configs_are_package_resources(self):
        """Every wpa_supplicant/hostapd config the runner may reference
        must be reachable via importlib.resources."""
        try:
            iso_pkg = res.files("honeysnatch.data.isolation")
        except (ModuleNotFoundError, AttributeError) as exc:
            pytest.fail(
                f"HS-05 regression: honeysnatch.data.isolation is not a "
                f"package. {exc}"
            )
        # The two canonical entry-point configs.
        for name in ("client.conf", "hostapd.conf"):
            assert (iso_pkg / name).is_file(), \
                f"HS-05 regression: {name} not shipped with the package"

    def test_reference_csvs_are_package_resources(self):
        try:
            data_pkg = res.files("honeysnatch.data")
        except (ModuleNotFoundError, AttributeError) as exc:
            pytest.fail(f"HS-05 regression: honeysnatch.data not a package. {exc}")
        for name in ("mccmnc.csv", "oui.csv"):
            assert (data_pkg / name).is_file(), \
                f"HS-05 regression: {name} not shipped with the package"


class TestFindDefaultConfigViaResources:
    """`find_default_config` MUST work when the package is installed
    (importlib.resources path) — not only when running from a source
    checkout."""

    def test_supplicant_config_resolves(self):
        from honeysnatch.isolation.config import find_default_config
        path = find_default_config("supplicant")
        assert path is not None, "HS-05 regression: cannot find client.conf"
        assert Path(path).exists()

    def test_hostapd_config_resolves(self):
        from honeysnatch.isolation.config import find_default_config
        path = find_default_config("hostapd")
        assert path is not None, "HS-05 regression: cannot find hostapd.conf"


class TestAllExtraIncludesEncryptedDb:
    """`pip install honeysnatch[all]` must include the SQLCipher driver —
    otherwise security.encrypt_database can't actually be honoured, and
    the storage factory (HS-04) fails closed as it should but with a
    misleading 'you asked for encryption but installed the wrong extra'
    error even after picking the ostensibly-complete extra."""

    def test_all_lists_encrypted_db(self):
        import re
        pyproject = (
            Path(__file__).resolve().parents[1] / "pyproject.toml"
        ).read_text()
        # Find the `all = [...]` block; ensure encrypted_db is in it.
        m = re.search(
            r"^all\s*=\s*\[\s*(.*?)\s*\]",
            pyproject, re.MULTILINE | re.DOTALL,
        )
        assert m, "no `all` extra defined"
        body = m.group(1)
        assert "encrypted_db" in body, \
            "HS-05 regression: `all` extra doesn't include encrypted_db"
