"""Tests for the isolation test runner."""
from honeysnatch.isolation.runner import IsolationTestRunner
from honeysnatch.isolation.attacks.base import AttackOutcome


def test_runner_creation():
    runner = IsolationTestRunner(interface="wlan0", config_file="test.conf")
    assert runner.interface == "wlan0"
    assert runner.config_file == "test.conf"


def test_runner_run_all():
    runner = IsolationTestRunner(interface="wlan0")
    session = runner.run_all("wlan1")
    assert session is not None
    assert len(session.results) > 0
    assert session.end_time is not None
    assert session.session_id


def test_runner_gtk_check():
    runner = IsolationTestRunner(interface="wlan0")
    result = runner.run_gtk_check("wlan1")
    assert result.outcome == AttackOutcome.INCONCLUSIVE


def test_runner_c2c():
    runner = IsolationTestRunner(interface="wlan0")
    result = runner.run_client2client("wlan1", mode="ip")
    assert result.outcome == AttackOutcome.INCONCLUSIVE
