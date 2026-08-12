"""Tamper-evident audit logger for honeysnatch.

Implements an append-only JSON-lines audit log with HMAC-SHA256
hash chaining.  Each entry includes:
  - sequential counter
  - ISO timestamp
  - event type and payload
  - HMAC of (previous_hash + current_entry)

Verification walks the chain and confirms every HMAC, detecting
any insertions, deletions, or modifications.

TAMPER-EVIDENCE CONTRACT (see review finding F-02):
The tamper-evidence guarantee is only meaningful if a corrupted or
truncated tail is a HARD FAILURE — never a "start a fresh chain and keep
writing" event. Earlier versions treated a bad tail as recoverable, which
meant an attacker who corrupted the last line could inject fresh, hash-
valid entries after the corruption point; verify() would flag the break
but a naive operator glancing at recent events would see "verified"
lines that were actually attacker-controlled.

The current design:
  - _read_chain_tail() raises AuditChainCorruptError on a bad tail.
  - AuditLogger construction propagates that error unless
    on_corrupt="rotate" is passed, in which case the tainted log is
    moved to <path>.tainted-<utc-ts> and a fresh chain is started with
    the first entry recording the rotation reason.
  - record() never silently begins a new chain.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

from honeysnatch.utils.crypto import get_or_create_hmac_key, hmac_sha256
from honeysnatch.utils.logger import get_logger

log = get_logger("audit")

# Sentinel hash for the very first entry in the chain
GENESIS_HASH = "0" * 64


class AuditChainCorruptError(RuntimeError):
    """Raised when the audit log's tail cannot be parsed.

    Callers should either abort (safest — the operator should look at the
    log manually) or explicitly opt into rotation via
    AuditLogger(on_corrupt="rotate").
    """


def _lock_exclusive(fd: int) -> None:
    """Take an exclusive advisory lock on an open file descriptor.

    Blocks. On Unix uses fcntl.flock; on Windows uses msvcrt.locking on
    the first byte of the file. A crash releases the lock automatically
    on both platforms.
    """
    if os.name == "nt":
        import msvcrt
        # msvcrt.locking locks against the current file pointer + nbytes.
        # Seek to 0, lock 1 byte, seek back to end (O_APPEND handles that
        # on write, but be explicit for clarity).
        pos = os.lseek(fd, 0, os.SEEK_CUR)
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)  # blocks
        os.lseek(fd, pos, os.SEEK_SET)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)


def _unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt
        pos = os.lseek(fd, 0, os.SEEK_CUR)
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        os.lseek(fd, pos, os.SEEK_SET)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)


class AuditLogger:
    """Append-only, HMAC-chained JSON-lines audit logger.

    Each line is a JSON object::

        {
            "seq": 1,
            "ts": "2025-01-15T12:34:56.789Z",
            "event": "scan_started",
            "data": {...},
            "prev_hash": "abc123...",
            "hash": "def456..."
        }

    The ``hash`` field is ``HMAC-SHA256(key, prev_hash + canonical_json)``,
    creating a tamper-evident chain.
    """

    def __init__(
        self,
        log_path: str,
        key_path: str = "",
        on_corrupt: Literal["abort", "rotate"] = "abort",
    ) -> None:
        """
        Args:
            log_path: Path to the audit log file (.jsonl).
            key_path: Path to HMAC key file.  If empty, derived from log_path.
            on_corrupt: What to do if the tail is unparseable.
                "abort" (default) raises AuditChainCorruptError — do NOT
                touch a suspicious log without operator review.
                "rotate" moves the tainted log aside to
                <path>.tainted-<utc-ts> and starts a fresh chain whose
                seq=1 entry records the rotation reason. Only pick this
                when you have an explicit process to review the rotated
                file afterward.
        """
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        if not key_path:
            key_path = str(self._log_path.with_suffix(".key"))
        self._hmac_key = get_or_create_hmac_key(key_path)

        self._lock = threading.Lock()

        try:
            self._seq, self._prev_hash = self._read_chain_tail()
        except AuditChainCorruptError as exc:
            if on_corrupt == "rotate":
                rotated_to = self._rotate_tainted_log(str(exc))
                self._seq, self._prev_hash = 0, GENESIS_HASH
                # First entry of the new chain records what happened —
                # this is discoverable evidence, not silent state loss.
                self.record(
                    "audit_chain_rotated",
                    {"reason": str(exc), "tainted_log": rotated_to},
                )
            else:
                raise

        log.debug("Audit logger ready: %s (seq=%d)", log_path, self._seq)

    def _read_chain_tail(self) -> tuple[int, str]:
        """Read AND cryptographically verify the ENTIRE chain.

        HS-03R remediation: the previous version verified only the tail
        HMAC. The reviewer showed that tampering with an EARLIER entry
        left the tail HMAC valid (its stored `prev_hash` field still
        matched its own content — the tail didn't re-hash earlier
        content), so `AuditLogger(path)` succeeded and record()
        appended entries chained from the forged-earlier-hash. verify()
        detected the mismatch later, but the fail-closed contract at
        init was broken.

        Now: walk every line, recompute each HMAC, require each entry's
        prev_hash to equal the previous entry's hash, and require the
        stored hash to match the recomputed value. Raise
        AuditChainCorruptError on ANY discrepancy — first, middle, or
        last.

        Slower than tail-only? Yes — O(n) in log size. Audit logs are
        typically small (hundreds to low thousands of entries per
        session). If this becomes a bottleneck, add a
        `checkpoint.jsonl` mechanism where the checkpoint is itself
        HMAC-authenticated with a separate key, and only verify the
        suffix since the last checkpoint. For v0.1.3 we prefer correct
        over fast.

        Raises AuditChainCorruptError on:
          - any line unparseable JSON
          - any line missing required fields
          - any stored HMAC that doesn't match its recomputed value
          - any prev_hash that doesn't chain from the previous entry

        Callers that want the older "start a fresh chain" behaviour
        must pass on_corrupt="rotate" to __init__.
        """
        if not self._log_path.exists() or self._log_path.stat().st_size == 0:
            return 0, GENESIS_HASH

        prev_hash = GENESIS_HASH
        last_seq = 0
        last_hash = GENESIS_HASH
        line_no = 0

        with open(self._log_path, "r") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                line_no += 1

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditChainCorruptError(
                        f"line {line_no} not valid JSON: {exc}"
                    ) from exc

                for req in ("seq", "hash", "prev_hash"):
                    if req not in entry:
                        raise AuditChainCorruptError(
                            f"line {line_no} missing required field {req!r}"
                        )

                if entry["prev_hash"] != prev_hash:
                    raise AuditChainCorruptError(
                        f"chain break at line {line_no} (seq={entry.get('seq')}): "
                        f"prev_hash does not chain from previous entry"
                    )

                stored_hash = entry["hash"]
                without_hash = {k: v for k, v in entry.items() if k != "hash"}
                canonical = json.dumps(
                    without_hash, sort_keys=True, separators=(",", ":"),
                )
                expected = hmac_sha256(
                    self._hmac_key, canonical.encode("utf-8"),
                )
                if stored_hash != expected:
                    raise AuditChainCorruptError(
                        f"HMAC mismatch at line {line_no} (seq={entry.get('seq')}): "
                        "entry content has been tampered"
                    )

                prev_hash = stored_hash
                last_seq = entry["seq"]
                last_hash = stored_hash

        return last_seq, last_hash

    def _rotate_tainted_log(self, reason: str) -> str:
        """Move the current log aside so a fresh chain can start.

        Returns the destination path so callers can log it. The suffix
        uses UTC to avoid ambiguity on timezone changes; the moved file
        is left readable so operators can investigate what was tampered.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = self._log_path.with_name(
            f"{self._log_path.name}.tainted-{ts}"
        )
        shutil.move(str(self._log_path), str(dest))
        log.error(
            "Audit chain corrupt (%s); moved to %s and starting fresh chain",
            reason, dest,
        )
        return str(dest)

    def record(self, event: str, data: Optional[dict[str, Any]] = None) -> dict:
        """Append a tamper-evident audit entry.

        HS-03 remediation: an inter-process advisory lock across the
        read-tail/sequence-derive/append/fsync cycle ensures two
        processes writing to the same log can't race sequences or
        interleave entries. In-process threading is still guarded by
        self._lock; the file lock is the second layer for multi-worker
        scenarios (systemd unit + one-shot CLI, cron scan + interactive
        session).

        Also fsyncs after each write so a power loss can't lose the
        last N events an operator was told were durable.

        Args:
            event: Event type (e.g. "scan_started", "export_csv", "alert_rogue_ap").
            data: Optional event payload.

        Returns:
            The recorded entry dict.
        """
        with self._lock:
            # Open with O_APPEND — kernel serializes single write() calls
            # of size <= PIPE_BUF, giving us atomic per-line appends.
            # The advisory flock guards the read-tail/hash/write cycle
            # against a concurrent audit-writing process.
            log_fd = os.open(
                str(self._log_path),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                0o600,
            )
            try:
                _lock_exclusive(log_fd)
                try:
                    # Re-read the tail so another process's writes since
                    # our last record() are picked up before we choose
                    # our own seq/prev_hash.
                    seq, prev_hash = self._read_chain_tail()
                    self._seq, self._prev_hash = seq, prev_hash

                    self._seq += 1
                    entry = {
                        "seq": self._seq,
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "event": event,
                        "data": data or {},
                        "prev_hash": self._prev_hash,
                    }

                    canonical = json.dumps(
                        entry, sort_keys=True, separators=(",", ":"),
                    )
                    entry_hash = hmac_sha256(
                        self._hmac_key, canonical.encode("utf-8"),
                    )
                    entry["hash"] = entry_hash
                    self._prev_hash = entry_hash

                    line = json.dumps(entry, separators=(",", ":")) + "\n"
                    os.write(log_fd, line.encode("utf-8"))
                    os.fsync(log_fd)
                finally:
                    _unlock(log_fd)
            finally:
                os.close(log_fd)

        return entry

    def verify(self) -> tuple[bool, int, str]:
        """Verify the entire audit chain.

        Returns:
            (valid, entries_checked, message)
        """
        if not self._log_path.exists():
            return True, 0, "No audit log found"

        prev_hash = GENESIS_HASH
        count = 0

        with open(self._log_path, "r") as f:
            for line_no, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    return False, count, f"Line {line_no}: invalid JSON"

                stored_hash = entry.pop("hash", "")
                count += 1

                if entry.get("prev_hash") != prev_hash:
                    return (
                        False, count,
                        f"Line {line_no} (seq {entry.get('seq')}): "
                        f"chain break - prev_hash mismatch",
                    )

                canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                expected = hmac_sha256(self._hmac_key, canonical.encode("utf-8"))

                if stored_hash != expected:
                    return (
                        False, count,
                        f"Line {line_no} (seq {entry.get('seq')}): "
                        f"HMAC mismatch - entry tampered",
                    )

                prev_hash = stored_hash

        return True, count, f"Chain verified: {count} entries OK"

    def get_entries(
        self,
        event_filter: str = "",
        limit: int = 0,
    ) -> list[dict]:
        """Read audit entries, optionally filtered.

        Args:
            event_filter: If set, only return entries matching this event type.
            limit: Maximum entries to return (0 = all).

        Returns:
            List of entry dicts (most recent last).
        """
        if not self._log_path.exists():
            return []

        entries = []
        with open(self._log_path, "r") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if event_filter and entry.get("event") != event_filter:
                    continue
                entries.append(entry)

        if limit > 0:
            entries = entries[-limit:]
        return entries

    @property
    def path(self) -> str:
        return str(self._log_path)

    @property
    def entry_count(self) -> int:
        return self._seq


def get_audit_logger(data_dir: str = "") -> AuditLogger:
    """Get or create the default audit logger.

    Args:
        data_dir: Data directory.  If empty, uses ~/.local/share/honeysnatch.

    Returns:
        AuditLogger instance.
    """
    if not data_dir:
        data_dir = str(Path.home() / ".local" / "share" / "honeysnatch")
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    log_path = str(Path(data_dir) / "audit.jsonl")
    return AuditLogger(log_path)
