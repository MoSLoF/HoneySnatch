"""Integration tests: loaded AppConfig reaches open_database (HS-04R).

Prior remediation added `honeysnatch/db/factory.py::open_database` and
proved it fails closed in unit tests. The v0.1.2 reviewer showed that
the CLI's Click context stored the loaded AppConfig but no command
passed it into open_database — every call site used `open_database(
db_path)`, causing the factory to fall back to `AppConfig()` defaults
and silently ignore an operator's `--config hardened.yaml`.

These tests invoke the actual CLI via Click's runner with a
non-default config file that enables encryption, and assert the
loaded config object is what `open_database` receives.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner


ENCRYPT_YAML = """
security:
  encrypt_database: true
  audit_enabled: true
"""


class _Capture:
    """Captures the config argument every open_database call receives."""

    def __init__(self):
        self.calls = []

    def __call__(self, db_path, config=None, passphrase=None):
        self.calls.append({
            "db_path": db_path,
            "config": config,
            "encrypt_flag": bool(config and config.security.encrypt_database),
        })
        # Return a stub DB manager just usable enough for the caller.
        class _StubDb:
            is_encrypted = True
            def list_sessions(self): return []
            def load_scan_session(self, sid): return None
            def close(self): pass
            def create_scan_session(self, **kw): return "stub-id"
            def get_session(self): return None
            def save_isolation_session(self, s): pass
        return _StubDb()


def _write_encrypt_yaml(tmp_path):
    p = tmp_path / "hardened.yaml"
    p.write_text(ENCRYPT_YAML)
    return str(p)


class TestExportCommandsPassConfig:
    @pytest.fixture
    def cli(self):
        from honeysnatch.cli.main import cli as cli_group
        return cli_group

    def test_export_csv_passes_loaded_config(self, cli, tmp_path):
        config_file = _write_encrypt_yaml(tmp_path)
        db = tmp_path / "session.db"
        db.write_bytes(b"stub")
        capture = _Capture()
        # Patch the factory where the CLI module actually imported it.
        with patch("honeysnatch.cli.export.open_database", capture):
            runner = CliRunner()
            result = runner.invoke(cli, [
                "--config", config_file,
                "export", "csv", str(db), "-o", str(tmp_path / "out.csv"),
            ])
        # The CLI shouldn't crash for undefined-name reasons.
        assert "NameError" not in (result.output + str(result.exception or "")), \
            "HS-04R/NR-01 regression: NameError in CLI path"
        # open_database must have been called with the loaded config.
        assert capture.calls, "open_database was never called"
        cfg = capture.calls[0]["config"]
        assert cfg is not None, \
            "HS-04R regression: open_database received config=None " \
            "(loaded AppConfig lost)"
        assert cfg.security.encrypt_database is True, \
            "HS-04R regression: --config hardened.yaml did not enable encryption"

    def test_export_json_passes_loaded_config(self, cli, tmp_path):
        config_file = _write_encrypt_yaml(tmp_path)
        db = tmp_path / "s.db"; db.write_bytes(b"stub")
        capture = _Capture()
        with patch("honeysnatch.cli.export.open_database", capture):
            runner = CliRunner()
            runner.invoke(cli, [
                "--config", config_file,
                "export", "json", str(db), "-o", str(tmp_path / "out.json"),
            ])
        assert capture.calls
        assert capture.calls[0]["encrypt_flag"] is True


class TestAnalyzeCommandsPassConfig:
    @pytest.mark.parametrize("subcmd", ["sessions", "aps", "clients", "summary"])
    def test_analyze_subcommand_passes_loaded_config(self, tmp_path, subcmd):
        from honeysnatch.cli.main import cli
        config_file = _write_encrypt_yaml(tmp_path)
        db = tmp_path / "s.db"; db.write_bytes(b"stub")
        capture = _Capture()
        with patch("honeysnatch.cli.analyze.open_database", capture):
            runner = CliRunner()
            runner.invoke(cli, [
                "--config", config_file,
                "analyze", subcmd, str(db),
            ])
        assert capture.calls, f"analyze {subcmd} did not call open_database"
        assert capture.calls[0]["encrypt_flag"] is True, \
            f"analyze {subcmd} lost the loaded config"


class TestIsolationRunAllPassesConfig:
    def test_isolation_run_all_output_db_uses_loaded_config(self, tmp_path, monkeypatch):
        from honeysnatch.cli.main import cli
        config_file = _write_encrypt_yaml(tmp_path)
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path / "consent"))
        monkeypatch.setenv("HOME", str(tmp_path))
        capture = _Capture()
        # run-all with --simulate skips hardware; we still expect the
        # DB open (if output_db is set) to receive the loaded config.
        with patch("honeysnatch.cli.isolation.open_database", capture):
            runner = CliRunner()
            runner.invoke(cli, [
                "--config", config_file,
                "isolation", "run-all",
                "-i", "wlan0", "-j", "wlan1",
                "--simulate",
                "--output-db", str(tmp_path / "iso.db"),
            ])
        # The persistence path is inside `if output_db:` guard; a successful
        # simulate run reaches it.
        assert capture.calls, "isolation --output-db did not reach open_database"
        assert capture.calls[0]["config"] is not None, \
            "HS-04R regression: isolation run-all discarded loaded config"


class TestSessionManagerAcceptsConfig:
    """The analysis SessionManager (used by GUI + CLI analyze) must
    accept and pass through an AppConfig."""

    def test_session_manager_forwards_config_to_factory(self, tmp_path):
        from honeysnatch.analysis.session_manager import SessionManager
        from honeysnatch.utils.config import AppConfig

        cfg = AppConfig()
        cfg.security.encrypt_database = True

        capture = _Capture()
        with patch("honeysnatch.analysis.session_manager.open_database", capture):
            mgr = SessionManager(config=cfg)
            # Point at a bogus path — the stub factory doesn't touch it.
            mgr.load_session(str(tmp_path / "s.db"))

        assert capture.calls
        assert capture.calls[0]["config"] is cfg, \
            "HS-04R regression: SessionManager didn't forward config"
