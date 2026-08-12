"""Tests for the isolation consent gate (review finding F-04).

Every live isolation entry point must refuse to run without either a
fresh --i-have-permission-to-attack acknowledgment or a stored consent
token bound to the specific target BSSID. --simulate bypasses the gate
but records a distinguishable audit entry. All grants, denials, and
simulate-mode runs land in the audit log.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from honeysnatch.isolation.consent import (
    BadBssidError,
    ConsentRequiredError,
    ConsentToken,
    canonicalize_bssid,
    grant_consent,
    load_consent,
    require_consent,
)


TARGET = "AA:BB:CC:DD:EE:FF"
CANONICAL = "aa:bb:cc:dd:ee:ff"


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Redirect the consent store to a tmpdir so tests never touch $HOME."""
    monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
    return tmp_path


class _RecordingAudit:
    """Stand-in audit logger that captures every record() call."""

    def __init__(self):
        self.events = []

    def record(self, event, data=None):
        self.events.append((event, dict(data or {})))
        return {"event": event, "data": data or {}}


# ══════════════════════════════════════════════════════════════════════
# BSSID canonicalization — must be strict; not-a-MAC never gets through
# ══════════════════════════════════════════════════════════════════════

class TestCanonicalize:
    def test_lowercases_and_strips(self):
        assert canonicalize_bssid(" AA:BB:CC:DD:EE:FF ") == CANONICAL

    @pytest.mark.parametrize("bad", [
        "not-a-mac",
        "aa:bb:cc:dd:ee",       # too few octets
        "aa:bb:cc:dd:ee:ff:00", # too many
        "aa-bb-cc-dd-ee-ff",    # wrong separator
        "gg:hh:ii:jj:kk:ll",    # not hex
        "",
        "  ",
    ])
    def test_rejects_bad_input(self, bad):
        with pytest.raises(BadBssidError):
            canonicalize_bssid(bad)


# ══════════════════════════════════════════════════════════════════════
# require_consent — the core gate
# ══════════════════════════════════════════════════════════════════════

class TestRequireConsent:
    def test_missing_target_refused(self, store):
        audit = _RecordingAudit()
        with pytest.raises(ConsentRequiredError):
            require_consent(bssid=None, ack_bssid=None,
                            simulate=False, audit_logger=audit)
        # A denial with no BSSID is not an isolation_consent_denied event
        # (no scope was named), so nothing gets audit-logged for that
        # class of user error — the ConsentRequiredError IS the log.
        assert audit.events == []

    def test_missing_ack_refused_and_audited(self, store):
        audit = _RecordingAudit()
        with pytest.raises(ConsentRequiredError):
            require_consent(bssid=TARGET, ack_bssid=None,
                            simulate=False, audit_logger=audit,
                            context={"command": "isolation test"})
        # Denial is recorded so a forensic reviewer sees WHO tried WHAT.
        assert len(audit.events) == 1
        ev, data = audit.events[0]
        assert ev == "isolation_consent_denied"
        assert data["bssid"] == CANONICAL

    def test_ack_matching_target_accepted(self, store):
        audit = _RecordingAudit()
        require_consent(bssid=TARGET, ack_bssid=TARGET.lower(),
                        simulate=False, audit_logger=audit,
                        context={"command": "isolation c2c"})
        assert len(audit.events) == 1
        ev, data = audit.events[0]
        assert ev == "isolation_consent_ack"
        assert data["form"] == "cli-flag"
        assert data["bssid"] == CANONICAL
        assert data["command"] == "isolation c2c"

    def test_ack_mismatched_target_refused(self, store):
        audit = _RecordingAudit()
        other = "11:22:33:44:55:66"
        with pytest.raises(ConsentRequiredError) as exc:
            require_consent(bssid=TARGET, ack_bssid=other,
                            simulate=False, audit_logger=audit)
        assert "does not match" in str(exc.value)

    def test_bad_ack_bssid_refused(self, store):
        audit = _RecordingAudit()
        with pytest.raises(ConsentRequiredError):
            require_consent(bssid=TARGET, ack_bssid="not-a-mac",
                            simulate=False, audit_logger=audit)

    def test_bad_target_bssid_raises(self, store):
        audit = _RecordingAudit()
        with pytest.raises(BadBssidError):
            require_consent(bssid="not-a-mac", ack_bssid=None,
                            simulate=False, audit_logger=audit)


# ══════════════════════════════════════════════════════════════════════
# --simulate bypass — audit trail must distinguish it from live runs
# ══════════════════════════════════════════════════════════════════════

class TestSimulateBypass:
    def test_simulate_without_target_ok(self, store):
        audit = _RecordingAudit()
        require_consent(bssid=None, ack_bssid=None,
                        simulate=True, audit_logger=audit,
                        context={"command": "isolation run-all"})
        assert len(audit.events) == 1
        ev, data = audit.events[0]
        assert ev == "isolation_simulate_run"
        assert data["command"] == "isolation run-all"

    def test_simulate_with_target_still_records_target(self, store):
        audit = _RecordingAudit()
        require_consent(bssid=TARGET, ack_bssid=None,
                        simulate=True, audit_logger=audit)
        ev, data = audit.events[0]
        assert ev == "isolation_simulate_run"
        assert data["bssid"] == TARGET


# ══════════════════════════════════════════════════════════════════════
# Persisted token path
# ══════════════════════════════════════════════════════════════════════

class TestPersistedToken:
    def test_grant_writes_file_with_0600(self, store):
        tok = grant_consent(TARGET, window_minutes=30, reason="lab test")
        path = store / f"{CANONICAL.replace(':', '')}.json"
        assert path.exists()
        # Mode 0600 from the start (F-05 pattern — no chmod race).
        assert (path.stat().st_mode & 0o777) == 0o600
        data = json.loads(path.read_text())
        assert data["bssid"] == CANONICAL
        assert data["reason"] == "lab test"

    def test_load_returns_token(self, store):
        grant_consent(TARGET, window_minutes=30)
        tok = load_consent(TARGET)
        assert tok is not None
        assert tok.bssid == CANONICAL

    def test_valid_token_lets_run_through(self, store):
        grant_consent(TARGET, window_minutes=60)
        audit = _RecordingAudit()
        require_consent(bssid=TARGET, ack_bssid=None,
                        simulate=False, audit_logger=audit)
        ev, data = audit.events[0]
        assert ev == "isolation_consent_token"
        assert data["form"] == "token"

    def test_expired_token_still_refused(self, store):
        # Grant with a normal window, then hand-edit expires_at into the past.
        grant_consent(TARGET, window_minutes=60)
        path = store / f"{CANONICAL.replace(':', '')}.json"
        data = json.loads(path.read_text())
        data["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        path.write_text(json.dumps(data))

        audit = _RecordingAudit()
        with pytest.raises(ConsentRequiredError):
            require_consent(bssid=TARGET, ack_bssid=None,
                            simulate=False, audit_logger=audit)
        assert audit.events[-1][0] == "isolation_consent_denied"

    def test_token_wrong_bssid_ignored(self, store):
        grant_consent("11:22:33:44:55:66", window_minutes=60)
        audit = _RecordingAudit()
        with pytest.raises(ConsentRequiredError):
            require_consent(bssid=TARGET, ack_bssid=None,
                            simulate=False, audit_logger=audit)

    def test_grant_rejects_absurd_window(self, store):
        with pytest.raises(ValueError):
            grant_consent(TARGET, window_minutes=0)
        with pytest.raises(ValueError):
            grant_consent(TARGET, window_minutes=99999)


# ══════════════════════════════════════════════════════════════════════
# End-to-end via the CLI  — the reviewer's proof-carrying acceptance
# ══════════════════════════════════════════════════════════════════════

class TestCliGate:
    """Exercise `fhs isolation c2m` via Click's runner — the shortest
    live path that exercises the gate without needing the hostap binary."""

    def _invoke(self, args, env=None):
        from click.testing import CliRunner
        from honeysnatch.cli.isolation import isolation as iso_group
        runner = CliRunner()
        return runner.invoke(iso_group, args, env=env)

    def test_cli_refuses_without_target_or_ack(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path / "consent"))
        monkeypatch.setenv("HOME", str(tmp_path))  # audit log lands here
        r = self._invoke(["c2m", "-i", "wlan0", "-m", "wlan1"])
        assert r.exit_code == 2
        assert "Refused" in r.output

    def test_cli_refuses_with_mismatched_ack(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path / "consent"))
        monkeypatch.setenv("HOME", str(tmp_path))
        r = self._invoke([
            "c2m", "-i", "wlan0", "-m", "wlan1",
            "-t", TARGET,
            "--i-have-permission-to-attack", "11:22:33:44:55:66",
        ])
        assert r.exit_code == 2
        assert "does not match" in r.output

    def test_cli_simulate_bypasses_gate(self, tmp_path, monkeypatch):
        """--simulate must not require target/ack. The exit code may be
        nonzero for downstream reasons (no hardware) but the consent
        message must NOT appear."""
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path / "consent"))
        monkeypatch.setenv("HOME", str(tmp_path))
        r = self._invoke(["c2m", "-i", "wlan0", "-m", "wlan1", "--simulate"])
        assert "Refused" not in r.output
