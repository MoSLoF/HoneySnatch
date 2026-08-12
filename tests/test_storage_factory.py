"""Tests for the storage factory that wires SecurityConfig (review HS-04).

Prior to the factory, `security.encrypt_database` and
`security.audit_enabled` had zero readers — flipping them on gave the
operator plaintext SQLite and silent audit anyway. These tests assert
the factory:

  1. Opens plaintext SQLite when encryption is off (matches old default).
  2. FAILS CLOSED when encryption is on but sqlcipher3 isn't installed.
  3. FAILS CLOSED when encryption is on but no passphrase is available.
  4. Passes the passphrase through when supplied.
  5. Emits audit events by default, and NONE when audit_enabled is off.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest

from honeysnatch.db.factory import (
    StorageConfigError,
    audit_event,
    open_database,
)
from honeysnatch.utils.config import AppConfig


# ══════════════════════════════════════════════════════════════════════
# encryption plumbing
# ══════════════════════════════════════════════════════════════════════

class TestEncryptionPlumbing:
    def test_plaintext_when_flag_off(self, tmp_path):
        """Default posture: SecurityConfig.encrypt_database=False → plain."""
        cfg = AppConfig()
        assert cfg.security.encrypt_database is False
        db = open_database(str(tmp_path / "plain.db"), config=cfg)
        assert db.is_encrypted is False
        db.close()

    def test_fails_closed_when_encryption_on_but_driver_missing(self, tmp_path):
        """Encryption flag on + no SQLCipher → StorageConfigError.
        The pre-factory behaviour silently gave plaintext."""
        cfg = AppConfig()
        cfg.security.encrypt_database = True

        # Simulate 'sqlcipher3 not installed'. Both driver modules refused.
        real_import = __import__
        def fake_import(name, *a, **kw):
            if name in ("sqlcipher3", "pysqlcipher3"):
                raise ImportError(f"stubbed absence of {name}")
            return real_import(name, *a, **kw)

        with patch("builtins.__import__", side_effect=fake_import):
            with pytest.raises(StorageConfigError) as exc:
                open_database(str(tmp_path / "e.db"), config=cfg,
                              passphrase="pw")
        assert "SQLCipher" in str(exc.value)

    def test_fails_closed_when_encryption_on_but_no_passphrase(
        self, tmp_path, monkeypatch,
    ):
        cfg = AppConfig()
        cfg.security.encrypt_database = True
        monkeypatch.delenv("HBV_DB_PASSPHRASE", raising=False)
        # Also make stdin non-TTY so the interactive path is refused.
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

        # Fake SQLCipher present so we get to the passphrase step.
        with patch("honeysnatch.db.factory._check_sqlcipher_available",
                   return_value=None):
            with pytest.raises(StorageConfigError) as exc:
                open_database(str(tmp_path / "e.db"), config=cfg)
        assert "passphrase" in str(exc.value).lower()

    def test_env_passphrase_is_honoured(self, tmp_path, monkeypatch):
        """When HBV_DB_PASSPHRASE is set, it reaches DatabaseManager."""
        cfg = AppConfig()
        cfg.security.encrypt_database = True
        monkeypatch.setenv("HBV_DB_PASSPHRASE", "correct-horse-battery-staple")

        captured = {}
        def fake_dbm(path, encryption_key=""):
            captured["key"] = encryption_key
            class _Stub:
                is_encrypted = True
                def close(self): pass
            return _Stub()

        with patch("honeysnatch.db.factory._check_sqlcipher_available",
                   return_value=None), \
             patch("honeysnatch.db.factory.DatabaseManager", fake_dbm), \
             patch("honeysnatch.db.factory.audit_event"):
            open_database(str(tmp_path / "e.db"), config=cfg)

        assert captured["key"] == "correct-horse-battery-staple"


# ══════════════════════════════════════════════════════════════════════
# audit plumbing
# ══════════════════════════════════════════════════════════════════════

class TestAuditPlumbing:
    def test_open_database_emits_open_event_by_default(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        cfg = AppConfig()
        cfg.security.audit_enabled = True
        db = open_database(str(tmp_path / "audit-on.db"), config=cfg)
        db.close()

        # The AuditLogger writes to $HOME/.local/share/honeysnatch/audit.jsonl
        audit_log = tmp_path / ".local" / "share" / "honeysnatch" / "audit.jsonl"
        assert audit_log.exists(), \
            "HS-04 regression: audit_enabled=True but no audit file created"
        content = audit_log.read_text()
        assert "database_opened" in content

    def test_open_database_silent_when_audit_disabled(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        cfg = AppConfig()
        cfg.security.audit_enabled = False

        # Also stub get_audit_logger so we can assert it's NOT called.
        called = {"n": 0}
        def fake_get_audit_logger(*a, **kw):
            called["n"] += 1
            raise AssertionError("audit_event must not touch the logger when disabled")

        with patch("honeysnatch.utils.audit.get_audit_logger",
                   side_effect=fake_get_audit_logger):
            db = open_database(str(tmp_path / "audit-off.db"), config=cfg)
            db.close()
        assert called["n"] == 0

    def test_audit_event_failure_does_not_break_caller(self, tmp_path, monkeypatch):
        """Audit is best-effort. A broken audit logger must NOT prevent
        the scan/export/whatever the caller was trying to do."""
        cfg = AppConfig()
        cfg.security.audit_enabled = True

        with patch("honeysnatch.utils.audit.get_audit_logger",
                   side_effect=RuntimeError("audit dead")):
            # Must not raise.
            audit_event("some_event", {}, config=cfg)


class TestAuditEventOrFailIsFailClosed:
    """HS-03R: security-critical events must fail-closed.

    `audit_event_or_fail` is the second half of the HS-03R
    remediation — best-effort telemetry keeps calling audit_event(),
    security-sensitive operations call audit_event_or_fail() and abort
    if the record cannot be captured.
    """

    def test_disabled_audit_raises(self):
        from honeysnatch.db.factory import (
            AuditDisabledError, audit_event_or_fail,
        )
        cfg = AppConfig()
        cfg.security.audit_enabled = False
        with pytest.raises(AuditDisabledError):
            audit_event_or_fail("consent_granted", {}, config=cfg)

    def test_writer_failure_raises(self):
        from honeysnatch.db.factory import (
            AuditWriteError, audit_event_or_fail,
        )
        cfg = AppConfig()
        cfg.security.audit_enabled = True
        with patch("honeysnatch.utils.audit.get_audit_logger",
                   side_effect=RuntimeError("disk full")):
            with pytest.raises(AuditWriteError):
                audit_event_or_fail("db_encrypted_open", {}, config=cfg)

    def test_healthy_writer_returns_normally(self, tmp_path, monkeypatch):
        from honeysnatch.db.factory import audit_event_or_fail
        monkeypatch.setenv("HOME", str(tmp_path))
        cfg = AppConfig()
        cfg.security.audit_enabled = True
        audit_event_or_fail("test_event", {"ok": True}, config=cfg)
        # Landed in the audit file.
        audit_log = tmp_path / ".local" / "share" / "honeysnatch" / "audit.jsonl"
        assert audit_log.exists()
        assert "test_event" in audit_log.read_text()


class TestEncryptedOpenIsFailClosedOnAudit:
    """NR-02: `audit_event_or_fail` isn't just a helper — it must be
    wired into the encrypted-DB open path so a broken audit trail
    stops the sensitive operation."""

    def test_encrypted_open_rolls_back_on_audit_write_failure(self, tmp_path):
        """Encrypted DB opens when audit write fails must NOT succeed —
        db.close() runs and the caller receives the audit exception."""
        from honeysnatch.db.factory import (
            AuditWriteError, open_database, StorageConfigError,
        )
        cfg = AppConfig()
        cfg.security.encrypt_database = True
        cfg.security.audit_enabled = True

        closed = {"called": False}

        class _StubEncryptedDb:
            is_encrypted = True
            def close(self): closed["called"] = True

        with patch("honeysnatch.db.factory._check_sqlcipher_available",
                   return_value=None), \
             patch("honeysnatch.db.factory.DatabaseManager",
                   return_value=_StubEncryptedDb()), \
             patch("honeysnatch.utils.audit.get_audit_logger",
                   side_effect=RuntimeError("audit dead")):
            with pytest.raises(AuditWriteError):
                open_database(str(tmp_path / "e.db"), config=cfg,
                              passphrase="pw")
        assert closed["called"], \
            "NR-02 regression: encrypted DB was not closed on audit failure"

    def test_encrypted_open_refuses_when_audit_disabled(self, tmp_path):
        """The operator flipped `encrypt_database=true` but not
        `audit_enabled` — that's a policy contradiction (the tamper-
        evidence claim depends on the audit trail). Fail-closed."""
        from honeysnatch.db.factory import (
            AuditDisabledError, open_database,
        )
        cfg = AppConfig()
        cfg.security.encrypt_database = True
        cfg.security.audit_enabled = False

        class _StubEncryptedDb:
            is_encrypted = True
            def close(self): pass

        with patch("honeysnatch.db.factory._check_sqlcipher_available",
                   return_value=None), \
             patch("honeysnatch.db.factory.DatabaseManager",
                   return_value=_StubEncryptedDb()):
            with pytest.raises(AuditDisabledError):
                open_database(str(tmp_path / "e.db"), config=cfg,
                              passphrase="pw")

    def test_plaintext_open_stays_best_effort_on_audit_failure(self, tmp_path):
        """Contrast: plaintext DB opens still use best-effort
        audit_event() — a broken audit log doesn't prevent an
        unencrypted scan session from starting. That's the
        documented policy split."""
        from honeysnatch.db.factory import open_database
        cfg = AppConfig()
        cfg.security.encrypt_database = False
        cfg.security.audit_enabled = True

        with patch("honeysnatch.utils.audit.get_audit_logger",
                   side_effect=RuntimeError("audit dead")):
            # Must NOT raise — plaintext open is best-effort.
            db = open_database(str(tmp_path / "plain.db"), config=cfg)
            db.close()


class TestConsentAuditIsFailClosed:
    """NR-02: consent acknowledgments are the operator-visible
    evidence that authorized a live attack. If the audit write fails,
    require_consent() must refuse to mint a receipt."""

    def test_broken_audit_prevents_consent_receipt(self, tmp_path, monkeypatch):
        from honeysnatch.isolation.consent import (
            ConsentRequiredError, require_consent,
        )
        monkeypatch.setenv("FHS_CONSENT_DIR", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))

        class _BrokenAudit:
            def record(self, event, data=None):
                raise RuntimeError("disk full")

        target = "AA:BB:CC:DD:EE:FF"
        with pytest.raises(ConsentRequiredError) as exc:
            require_consent(bssid=target, ack_bssid=target, simulate=False,
                            audit_logger=_BrokenAudit())
        assert "audit" in str(exc.value).lower()
