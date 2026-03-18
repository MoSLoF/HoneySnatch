"""Tests for CLI isolation subcommand registration."""
from click.testing import CliRunner

from honeysnatch.cli.main import cli


def test_isolation_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["isolation", "--help"])
    assert result.exit_code == 0
    assert "Client isolation" in result.output


def test_isolation_test_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["isolation", "test", "--help"])
    assert result.exit_code == 0
    assert "--interface" in result.output


def test_isolation_c2c_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["isolation", "c2c", "--help"])
    assert result.exit_code == 0
    assert "--second-interface" in result.output


def test_isolation_c2m_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["isolation", "c2m", "--help"])
    assert result.exit_code == 0
    assert "--monitor-interface" in result.output


def test_isolation_run_all_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["isolation", "run-all", "--help"])
    assert result.exit_code == 0


def test_isolation_setup_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["isolation", "setup", "--help"])
    assert result.exit_code == 0
    assert "gtkabuse" in result.output


def test_isolation_build_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["isolation", "build", "--help"])
    assert result.exit_code == 0
    assert "hostap_2_10" in result.output
