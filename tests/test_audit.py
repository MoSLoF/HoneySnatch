"""Tests for tamper-evident audit logger."""

import json
import os

import pytest

from honeysnatch.utils.audit import GENESIS_HASH, AuditLogger


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
        """HS-03R contract change: reopen of a tampered log MUST fail
        closed at init, not silently succeed and then report on
        explicit verify(). This test now asserts the fail-closed shape."""
        from honeysnatch.utils.audit import AuditChainCorruptError

        audit.record("legit_event", {"amount": 100})
        audit.record("another_event")

        with open(audit.path, "r") as f:
            lines = f.readlines()

        entry = json.loads(lines[0])
        entry["data"]["amount"] = 999  # Tamper!
        lines[0] = json.dumps(entry) + "\n"

        with open(audit.path, "w") as f:
            f.writelines(lines)

        # Init fails closed — attacker-forged content cannot chain
        # from an accepted state.
        with pytest.raises(AuditChainCorruptError) as exc:
            AuditLogger(audit.path)
        assert "hmac" in str(exc.value).lower()

    def test_verify_detects_deleted_entry(self, audit):
        from honeysnatch.utils.audit import AuditChainCorruptError

        audit.record("event1")
        audit.record("event2")
        audit.record("event3")

        with open(audit.path, "r") as f:
            lines = f.readlines()

        with open(audit.path, "w") as f:
            f.write(lines[0])
            f.write(lines[2])  # Skip line[1]

        # Init fails closed on the chain break.
        with pytest.raises(AuditChainCorruptError) as exc:
            AuditLogger(audit.path)
        assert "chain break" in str(exc.value).lower() or "prev_hash" in str(exc.value).lower()


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


class TestCorruptTailFailSafe:
    """Review finding F-02: a corrupt/truncated tail must NOT silently
    reset the chain. Default is to raise; rotation is an explicit opt-in
    that leaves the tainted log discoverable and records the rotation
    reason as the first entry of the new chain."""

    def _seed_valid_chain(self, tmp_path):
        from honeysnatch.utils.audit import AuditLogger
        log_path = str(tmp_path / "audit.jsonl")
        a = AuditLogger(log_path)
        a.record("scan_start")
        a.record("scan_end")
        return log_path

    def test_default_aborts_on_corrupt_tail(self, tmp_path):
        from honeysnatch.utils.audit import (
            AuditLogger, AuditChainCorruptError,
        )
        log_path = self._seed_valid_chain(tmp_path)
        # Corrupt the tail — append a partial JSON fragment as an
        # attacker would after truncating mid-write.
        with open(log_path, "a") as f:
            f.write('{"seq": 3, "ts": "2026-01-01", "ev\n')

        with pytest.raises(AuditChainCorruptError):
            AuditLogger(log_path)

    def test_default_aborts_on_missing_required_fields(self, tmp_path):
        from honeysnatch.utils.audit import (
            AuditLogger, AuditChainCorruptError,
        )
        log_path = self._seed_valid_chain(tmp_path)
        # A parseable JSON line with the hash field stripped — an
        # attacker who thinks they know the schema.
        with open(log_path, "a") as f:
            f.write('{"seq": 3, "ts": "x", "event": "fake"}\n')

        with pytest.raises(AuditChainCorruptError):
            AuditLogger(log_path)

    def test_rotate_option_moves_tainted_log_aside(self, tmp_path):
        from honeysnatch.utils.audit import AuditLogger
        log_path = self._seed_valid_chain(tmp_path)
        with open(log_path, "a") as f:
            f.write('{"seq": 3, "ts": "x", "ev\n')

        a = AuditLogger(log_path, on_corrupt="rotate")

        # A tainted file exists alongside the fresh log.
        tainted = list(tmp_path.glob("audit.jsonl.tainted-*"))
        assert len(tainted) == 1, f"expected one rotated file, found {tainted}"

        # The fresh log's first entry records the rotation reason.
        entries = a.get_entries()
        assert len(entries) == 1
        assert entries[0]["event"] == "audit_chain_rotated"
        assert "tainted_log" in entries[0]["data"]
        assert entries[0]["seq"] == 1
        assert entries[0]["prev_hash"] == "0" * 64

    def test_rotate_produces_verifiable_new_chain(self, tmp_path):
        from honeysnatch.utils.audit import AuditLogger
        log_path = self._seed_valid_chain(tmp_path)
        with open(log_path, "a") as f:
            f.write('{"seq": 3, "ts": "x", "ev\n')

        a = AuditLogger(log_path, on_corrupt="rotate")
        a.record("scan_start")
        valid, count, _ = a.verify()
        assert valid is True
        assert count == 2  # rotation-notice + scan_start

    def test_valid_chain_never_triggers_rotation(self, tmp_path):
        """Rotation must ONLY happen on actual corruption — a clean
        resume across restarts must not create tainted files."""
        from honeysnatch.utils.audit import AuditLogger
        log_path = self._seed_valid_chain(tmp_path)

        AuditLogger(log_path, on_corrupt="rotate")  # should be no-op
        AuditLogger(log_path, on_corrupt="rotate")  # ditto

        tainted = list(tmp_path.glob("audit.jsonl.tainted-*"))
        assert tainted == [], f"unexpected rotation: {tainted}"


class TestHmacTamperRejected:
    """Review finding HS-03 — the reviewer's exact probe.

    Prior remediation only checked JSON shape + presence of required
    fields, so an attacker could rewrite the tail's `data` and keep
    `seq`/`hash` as valid strings; init would accept it and subsequent
    record() would chain from the forged hash. verify() detected the
    mismatch later, but the fail-closed contract was broken.
    """

    def _seed(self, tmp_path):
        from honeysnatch.utils.audit import AuditLogger
        log_path = str(tmp_path / "audit.jsonl")
        a = AuditLogger(log_path)
        a.record("scan_started", {"iface": "wlan0"})
        a.record("ap_found", {"bssid": "aa:bb:cc:dd:ee:ff"})
        return log_path

    def test_reviewer_hs03_probe_forged_data_rejected(self, tmp_path):
        """The reviewer's exact probe: parseable-shape but tampered-data
        tail must cause init to raise AuditChainCorruptError."""
        import json as _json
        from honeysnatch.utils.audit import (
            AuditChainCorruptError, AuditLogger,
        )

        log_path = self._seed(tmp_path)

        # Rewrite the last line's `data` field, preserving seq/hash as
        # valid strings — exactly the pre-remediation bypass.
        with open(log_path) as f:
            lines = [line for line in f if line.strip()]
        last = _json.loads(lines[-1])
        last["data"] = {"bssid": "ff:ff:ff:ff:ff:ff"}  # attacker-forged
        lines[-1] = _json.dumps(last, separators=(",", ":")) + "\n"
        with open(log_path, "w") as f:
            f.writelines(lines)

        with pytest.raises(AuditChainCorruptError) as exc:
            AuditLogger(log_path)
        assert "hmac" in str(exc.value).lower()

    def test_forged_hash_field_rejected(self, tmp_path):
        """A tail whose `hash` field is a valid-looking hex string but
        does not match the entry's recomputed HMAC must also be refused."""
        import json as _json
        from honeysnatch.utils.audit import (
            AuditChainCorruptError, AuditLogger,
        )

        log_path = self._seed(tmp_path)
        with open(log_path) as f:
            lines = [line for line in f if line.strip()]
        last = _json.loads(lines[-1])
        last["hash"] = "0" * 64  # syntactically valid, cryptographically wrong
        lines[-1] = _json.dumps(last, separators=(",", ":")) + "\n"
        with open(log_path, "w") as f:
            f.writelines(lines)

        with pytest.raises(AuditChainCorruptError):
            AuditLogger(log_path)

    def test_clean_tail_still_resumes(self, tmp_path):
        """Sanity: a legitimate resume across restarts still works."""
        from honeysnatch.utils.audit import AuditLogger
        log_path = self._seed(tmp_path)
        # No tampering — reopen should succeed.
        a = AuditLogger(log_path)
        entry = a.record("scan_ended", {})
        assert entry["seq"] == 3

    def test_log_file_created_0600(self, tmp_path):
        """HS-03 side-fix: the log file itself should be created 0600."""
        import stat
        if os.name == "nt":
            pytest.skip("POSIX perm check")
        from honeysnatch.utils.audit import AuditLogger
        log_path = tmp_path / "audit.jsonl"
        a = AuditLogger(str(log_path))
        a.record("test", {})
        assert log_path.exists()
        mode = stat.S_IMODE(log_path.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_reviewer_hs03r_probe_earlier_entry_tamper_rejected(self, tmp_path):
        """HS-03R (v0.1.2 review): the reviewer's EXACT probe.

        Create a 2-entry chain; modify entry #1's `data` while leaving
        entry #2 (and its stored hash + prev_hash) intact. Pre-remediation,
        AuditLogger reopened successfully because only the tail HMAC was
        checked. Post-remediation (full-chain verify on init), reopen
        MUST raise AuditChainCorruptError at line 1.
        """
        import json as _json
        from honeysnatch.utils.audit import (
            AuditChainCorruptError, AuditLogger,
        )
        log_path = self._seed(tmp_path)  # writes entries seq=1 (scan_started) and seq=2 (ap_found)

        # Tamper with entry #1 only — leave entry #2 untouched.
        with open(log_path) as f:
            lines = [line for line in f if line.strip()]
        assert len(lines) == 2
        first = _json.loads(lines[0])
        first["data"] = {"forged": True}  # keep seq/hash/prev_hash as-is
        lines[0] = _json.dumps(first, separators=(",", ":")) + "\n"
        with open(log_path, "w") as f:
            f.writelines(lines)

        # Reopen — must fail closed. Prior version accepted; a subsequent
        # record() then appended seq=3 chained from the FORGED hash.
        with pytest.raises(AuditChainCorruptError) as exc:
            AuditLogger(log_path)
        # The error must name the earlier line, not just the tail.
        assert "line 1" in str(exc.value) or "seq=1" in str(exc.value), \
            f"HS-03R regression: earlier-line tamper not detected: {exc.value}"

    def test_middle_line_tamper_rejected(self, tmp_path):
        """Same as above but with a 3-entry chain, tampering the middle."""
        import json as _json
        from honeysnatch.utils.audit import (
            AuditChainCorruptError, AuditLogger,
        )
        log_path = str(tmp_path / "audit.jsonl")
        a = AuditLogger(log_path)
        a.record("e1")
        a.record("e2")
        a.record("e3")

        with open(log_path) as f:
            lines = [line for line in f if line.strip()]
        mid = _json.loads(lines[1])
        mid["data"] = {"forged": True}
        lines[1] = _json.dumps(mid, separators=(",", ":")) + "\n"
        with open(log_path, "w") as f:
            f.writelines(lines)

        with pytest.raises(AuditChainCorruptError):
            AuditLogger(log_path)

    def test_deleted_middle_line_rejected(self, tmp_path):
        from honeysnatch.utils.audit import (
            AuditChainCorruptError, AuditLogger,
        )
        log_path = str(tmp_path / "audit.jsonl")
        a = AuditLogger(log_path)
        a.record("e1"); a.record("e2"); a.record("e3")

        with open(log_path) as f:
            lines = [line for line in f if line.strip()]
        del lines[1]  # remove middle entry
        with open(log_path, "w") as f:
            f.writelines(lines)

        with pytest.raises(AuditChainCorruptError):
            AuditLogger(log_path)

    def test_reordered_lines_rejected(self, tmp_path):
        from honeysnatch.utils.audit import (
            AuditChainCorruptError, AuditLogger,
        )
        log_path = str(tmp_path / "audit.jsonl")
        a = AuditLogger(log_path)
        a.record("e1"); a.record("e2"); a.record("e3")

        with open(log_path) as f:
            lines = [line for line in f if line.strip()]
        lines[0], lines[1] = lines[1], lines[0]
        with open(log_path, "w") as f:
            f.writelines(lines)

        with pytest.raises(AuditChainCorruptError):
            AuditLogger(log_path)

    def test_two_process_race_preserves_sequence(self, tmp_path):
        """Inter-process file lock: two writers must produce a
        monotonically increasing sequence with no duplicates."""
        import multiprocessing as mp
        from honeysnatch.utils.audit import AuditLogger

        log_path = str(tmp_path / "audit.jsonl")

        def _writer(path, count):
            a = AuditLogger(path)
            for i in range(count):
                a.record(f"event-{os.getpid()}-{i}")

        procs = [
            mp.Process(target=_writer, args=(log_path, 20))
            for _ in range(3)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=15)
            assert p.exitcode == 0, f"writer exited with {p.exitcode}"

        # Verify the chain is intact and sequences are 1..60 with no gaps.
        a = AuditLogger(log_path)
        valid, count, msg = a.verify()
        assert valid is True, msg
        assert count == 60
        entries = a.get_entries()
        seqs = [e["seq"] for e in entries]
        assert seqs == list(range(1, 61)), \
            f"HS-03 regression: sequence race — got {seqs[:10]}...{seqs[-10:]}"
