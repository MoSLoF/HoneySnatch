"""Tests for tamper-evident audit logger."""

import json

import pytest

from flyinghoneysnitch.utils.audit import GENESIS_HASH, AuditLogger


@pytest.fixture
def audit(tmp_path):
    log_path = str(tmp_path / "audit.jsonl")
    return AuditLogger(log_path)


class TestAuditRecording:

    def test_record_creates_entry(self, audit):
        entry = audit.record("test_event", {"key": "value"})
        assert entry["seq"] == 1
        assert entry["event"] == "test_event"
        assert entry["data"] == {"key": "value"}
        assert "hash" in entry
        assert "prev_hash" in entry

    def test_sequential_numbering(self, audit):
        audit.record("event1")
        e2 = audit.record("event2")
        e3 = audit.record("event3")
        assert e2["seq"] == 2
        assert e3["seq"] == 3

    def test_chain_linkage(self, audit):
        e1 = audit.record("event1")
        e2 = audit.record("event2")
        assert e2["prev_hash"] == e1["hash"]

    def test_first_entry_genesis_hash(self, audit):
        e = audit.record("first")
        assert e["prev_hash"] == GENESIS_HASH

    def test_entry_count(self, audit):
        assert audit.entry_count == 0
        audit.record("e1")
        audit.record("e2")
        assert audit.entry_count == 2


class TestAuditVerification:

    def test_verify_empty_log(self, audit):
        valid, count, msg = audit.verify()
        assert valid is True
        assert count == 0

    def test_verify_valid_chain(self, audit):
        for i in range(10):
            audit.record(f"event_{i}", {"i": i})
        valid, count, msg = audit.verify()
        assert valid is True
        assert count == 10

    def test_verify_detects_tampered_entry(self, audit):
        audit.record("legit_event", {"amount": 100})
        audit.record("another_event")

        # Tamper with the log file
        with open(audit.path, "r") as f:
            lines = f.readlines()

        entry = json.loads(lines[0])
        entry["data"]["amount"] = 999  # Tamper!
        lines[0] = json.dumps(entry) + "\n"

        with open(audit.path, "w") as f:
            f.writelines(lines)

        # Re-create logger to reload
        tampered_audit = AuditLogger(audit.path)
        valid, count, msg = tampered_audit.verify()
        assert valid is False
        assert "HMAC mismatch" in msg

    def test_verify_detects_deleted_entry(self, audit):
        audit.record("event1")
        audit.record("event2")
        audit.record("event3")

        # Delete middle entry
        with open(audit.path, "r") as f:
            lines = f.readlines()

        with open(audit.path, "w") as f:
            f.write(lines[0])
            f.write(lines[2])  # Skip line[1]

        tampered_audit = AuditLogger(audit.path)
        valid, count, msg = tampered_audit.verify()
        assert valid is False
        assert "chain break" in msg


class TestAuditFiltering:

    def test_get_all_entries(self, audit):
        audit.record("scan_start")
        audit.record("ap_found")
        audit.record("scan_end")
        entries = audit.get_entries()
        assert len(entries) == 3

    def test_filter_by_event(self, audit):
        audit.record("scan_start")
        audit.record("ap_found")
        audit.record("ap_found")
        audit.record("scan_end")
        entries = audit.get_entries(event_filter="ap_found")
        assert len(entries) == 2

    def test_limit_entries(self, audit):
        for i in range(20):
            audit.record(f"event_{i}")
        entries = audit.get_entries(limit=5)
        assert len(entries) == 5
        # Should be the last 5
        assert entries[0]["seq"] == 16


class TestAuditResuming:

    def test_resume_chain(self, tmp_path):
        log_path = str(tmp_path / "audit.jsonl")

        a1 = AuditLogger(log_path)
        a1.record("event1")
        e2 = a1.record("event2")

        # Create new instance — should resume from last entry
        a2 = AuditLogger(log_path)
        e3 = a2.record("event3")
        assert e3["seq"] == 3
        assert e3["prev_hash"] == e2["hash"]

        # Verify entire chain
        valid, count, msg = a2.verify()
        assert valid is True
        assert count == 3
