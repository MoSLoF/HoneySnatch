"""Multi-session comparison and management for HoneyView.

Loads, compares, and correlates data across multiple scan sessions
to identify changes, trends, and anomalies over time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from flyinghoneysnitch.core.models import AccessPoint, Client, ScanSession
from flyinghoneysnitch.db.database import DatabaseManager
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("session_manager")


@dataclass
class SessionDiff:
    """Differences between two scan sessions."""

    new_aps: list[AccessPoint] = field(default_factory=list)
    removed_aps: list[AccessPoint] = field(default_factory=list)
    changed_aps: list[tuple[AccessPoint, AccessPoint]] = field(default_factory=list)  # (old, new)
    new_clients: list[Client] = field(default_factory=list)
    removed_clients: list[Client] = field(default_factory=list)
    ssid_changes: list[tuple[str, str, str]] = field(default_factory=list)  # (bssid, old_ssid, new_ssid)
    encryption_changes: list[tuple[str, str, str]] = field(default_factory=list)  # (bssid, old_enc, new_enc)


class SessionManager:
    """Manages and compares multiple scan sessions.

    Loads sessions from database files and provides comparison
    and correlation capabilities for post-hoc analysis.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, ScanSession] = {}
        self._db_managers: dict[str, DatabaseManager] = {}

    def load_session(self, db_path: str) -> Optional[ScanSession]:
        """Load a scan session from a database file.

        Args:
            db_path: Path to the .db session file.

        Returns:
            The loaded ScanSession, or None if loading fails.
        """
        try:
            db = DatabaseManager(db_path)
            sessions = db.list_sessions()
            if not sessions:
                log.warning("No sessions in %s", db_path)
                db.close()
                return None

            session = db.load_scan_session(sessions[0]["session_id"])
            if session:
                self._sessions[session.session_id] = session
                self._db_managers[session.session_id] = db
                log.info("Loaded session: %s (%d APs, %d clients)",
                         session.name, session.ap_count, session.client_count)
            return session

        except Exception as e:
            log.error("Failed to load session from %s: %s", db_path, e)
            return None

    def load_directory(self, directory: str) -> list[ScanSession]:
        """Load all session databases from a directory.

        Args:
            directory: Path to directory containing .db files.

        Returns:
            List of loaded sessions, sorted by start time.
        """
        sessions = []
        for db_file in sorted(Path(directory).glob("*.db")):
            session = self.load_session(str(db_file))
            if session:
                sessions.append(session)

        sessions.sort(key=lambda s: s.start_time)
        log.info("Loaded %d sessions from %s", len(sessions), directory)
        return sessions

    def compare_sessions(
        self,
        session_a: ScanSession,
        session_b: ScanSession,
    ) -> SessionDiff:
        """Compare two sessions to find differences.

        Args:
            session_a: The baseline/earlier session.
            session_b: The comparison/later session.

        Returns:
            SessionDiff with new, removed, and changed items.
        """
        diff = SessionDiff()

        # Compare APs
        a_bssids = set(session_a.access_points.keys())
        b_bssids = set(session_b.access_points.keys())

        # New APs (in B but not A)
        for bssid in b_bssids - a_bssids:
            diff.new_aps.append(session_b.access_points[bssid])

        # Removed APs (in A but not B)
        for bssid in a_bssids - b_bssids:
            diff.removed_aps.append(session_a.access_points[bssid])

        # Changed APs (in both)
        for bssid in a_bssids & b_bssids:
            ap_a = session_a.access_points[bssid]
            ap_b = session_b.access_points[bssid]

            changed = False

            # SSID change
            if ap_a.ssid != ap_b.ssid:
                diff.ssid_changes.append((bssid, ap_a.ssid, ap_b.ssid))
                changed = True

            # Encryption change
            if ap_a.encryption != ap_b.encryption:
                diff.encryption_changes.append(
                    (bssid, ap_a.encryption.value, ap_b.encryption.value)
                )
                changed = True

            # Channel change or significant signal change
            if ap_a.channel != ap_b.channel or abs(ap_a.rssi - ap_b.rssi) > 10:
                changed = True

            if changed:
                diff.changed_aps.append((ap_a, ap_b))

        # Compare clients
        a_macs = set(session_a.clients.keys())
        b_macs = set(session_b.clients.keys())

        for mac in b_macs - a_macs:
            diff.new_clients.append(session_b.clients[mac])

        for mac in a_macs - b_macs:
            diff.removed_clients.append(session_a.clients[mac])

        return diff

    def find_persistent_aps(self, sessions: list[ScanSession]) -> dict[str, int]:
        """Find APs that appear across multiple sessions.

        Returns:
            Dict of BSSID -> number of sessions it appeared in.
        """
        ap_counts: dict[str, int] = {}
        for session in sessions:
            for bssid in session.access_points:
                ap_counts[bssid] = ap_counts.get(bssid, 0) + 1
        return ap_counts

    def find_transient_aps(
        self,
        sessions: list[ScanSession],
        max_appearances: int = 1,
    ) -> list[AccessPoint]:
        """Find APs that appear in only a few sessions (potentially rogue)."""
        ap_counts = self.find_persistent_aps(sessions)
        transient = []
        for bssid, count in ap_counts.items():
            if count <= max_appearances:
                # Find the AP from the session where it appeared
                for session in sessions:
                    if bssid in session.access_points:
                        transient.append(session.access_points[bssid])
                        break
        return transient

    def get_session(self, session_id: str) -> Optional[ScanSession]:
        """Get a loaded session by ID."""
        return self._sessions.get(session_id)

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    def close_all(self) -> None:
        """Close all database connections."""
        for db in self._db_managers.values():
            db.close()
        self._db_managers.clear()
        self._sessions.clear()
