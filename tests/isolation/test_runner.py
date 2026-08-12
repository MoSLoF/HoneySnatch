"""Tests for the isolation test runner.

The `gtk_check` and `c2c` runner tests need the hostap wpa_supplicant
binary that must be compiled via `vendor/build.sh` (libnl / libssl /
libdbus system dependencies required). CI environments without those
system packages should skip rather than fail — the tests still run
locally on a developer box or on the HackberryPi deployment target.
"""
from pathlib import Path

import pytest

from honeysnatch.isolation.runner import IsolationTestRunner
from honeysnatch.isolation.attacks.base import AttackOutcome


HOSTAP_BIN = (
    Path(__file__).resolve().parents[2]
    / "vendor" / "hostap_2_10" / "wpa_supplicant" / "wpa_supplicant"
)

_hostap_missing = pytest.mark.skipif(
    not HOSTAP_BIN.exists(),
    reason=(
        "hostap wpa_supplicant binary not compiled — run vendor/build.sh "
        "with libnl / libssl / libdbus installed to enable this test."
    ),
)


def test_runner_creation():
    runner = IsolationTestRunner(interface="wlan0", config_file="test.conf")
    assert runner.interface == "wlan0"
    assert runner.config_file == "test.conf"


def test_runner_run_all():
    # Runner now refuses live runs without an Authorization (HS-02).
    # Simulate mode is the correct dry-run smoke test — this construction
    # is what a CI env without hardware / a browser-based caller / any
    # third-party integration should use.
    runner = IsolationTestRunner(interface="wlan0", simulate=True)
    session = runner.run_all("wlan1")
    assert session is not None
    assert len(session.results) > 0
    assert session.end_time is not None
    assert session.session_id


@_hostap_missing
def test_runner_gtk_check():
    runner = IsolationTestRunner(interface="wlan0")
    result = runner.run_gtk_check("wlan1")
    assert result.outcome == AttackOutcome.INCONCLUSIVE


@_hostap_missing
def test_runner_c2c():
    runner = IsolationTestRunner(interface="wlan0")
    result = runner.run_client2client("wlan1", mode="ip")
    assert result.outcome == AttackOutcome.INCONCLUSIVE
