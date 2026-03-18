"""Tamper-evident audit logger for honeysnatch.

Implements an append-only JSON-lines audit log with HMAC-SHA256
hash chaining.  Each entry includes:
  - sequential counter
  - ISO timestamp
  - event type and payload
  - HMAC of (previous_hash + current_entry)

Verification walks the chain and confirms every HMAC, detecting
any insertions, deletions, or modifications.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from honeysnatch.utils.crypto import get_or_create_hmac_key, hmac_sha256
from honeysnatch.utils.logger import get_logger

log = get_logger("audit")

# Sentinel hash for the very first entry in the chain
GENESIS_HASH = "0" * 64


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

    def __init__(self, log_path: str, key_path: str = "") -> None:
        """
        Args:
            log_path: Path to the audit log file (.jsonl).
            key_path: Path to HMAC key file.  If empty, derived from log_path.
        """
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        if not key_path:
            key_path = str(self._log_path.with_suffix(".key"))
        self._hmac_key = get_or_create_hmac_key(key_path)

        self._lock = threading.Lock()
        self._seq, self._prev_hash = self._read_chain_tail()
        log.debug("Audit logger ready: %s (seq=%d)", log_path, self._seq)

    def _read_chain_tail(self) -> tuple[int, str]:
        """Read the last entry to resume the chain."""
        if not self._log_path.exists() or self._log_path.stat().st_size == 0:
            return 0, GENESIS_HASH

        # Read last non-empty line
        last_line = ""
        with open(self._log_path, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    last_line = stripped

        if not last_line:
            return 0, GENESIS_HASH

        try:
            entry = json.loads(last_line)
            return entry["seq"], entry["hash"]
        except (json.JSONDecodeError, KeyError):
            log.warning("Corrupt audit log tail, starting fresh chain")
            return 0, GENESIS_HASH

    def record(self, event: str, data: Optional[dict[str, Any]] = None) -> dict:
        """Append a tamper-evident audit entry.

        Args:
            event: Event type (e.g. "scan_started", "export_csv", "alert_rogue_ap").
            data: Optional event payload.

        Returns:
            The recorded entry dict.
        """
        with self._lock:
            self._seq += 1
            entry = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "data": data or {},
                "prev_hash": self._prev_hash,
            }

            # Canonical JSON for hashing (sorted keys, no whitespace)
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            entry_hash = hmac_sha256(self._hmac_key, canonical.encode("utf-8"))
            entry["hash"] = entry_hash
            self._prev_hash = entry_hash

            with open(self._log_path, "a") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")

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
