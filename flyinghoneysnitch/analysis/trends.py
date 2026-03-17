"""Time-series trend analysis for HoneyView.

Analyzes device appearance, disappearance, signal trends,
and temporal patterns across scan sessions.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from flyinghoneysnitch.core.models import AccessPoint, Client, ScanSession
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("trends")


@dataclass
class DeviceTrend:
    """Trend data for a single device over time."""

    identifier: str  # BSSID or MAC
    label: str  # SSID or vendor
    timestamps: list[datetime] = field(default_factory=list)
    rssi_values: list[int] = field(default_factory=list)
    channels: list[int] = field(default_factory=list)

    @property
    def avg_rssi(self) -> float:
        return sum(self.rssi_values) / len(self.rssi_values) if self.rssi_values else -100

    @property
    def rssi_range(self) -> tuple[int, int]:
        if not self.rssi_values:
            return (-100, -100)
        return (min(self.rssi_values), max(self.rssi_values))

    @property
    def duration(self) -> timedelta:
        if len(self.timestamps) < 2:
            return timedelta(0)
        return self.timestamps[-1] - self.timestamps[0]


@dataclass
class TimeSlot:
    """Activity summary for a time window."""

    start: datetime
    end: datetime
    ap_count: int = 0
    client_count: int = 0
    new_aps: int = 0
    lost_aps: int = 0


class TrendAnalyzer:
    """Analyzes temporal trends across scan sessions.

    Tracks how devices appear, disappear, and change over time
    to identify patterns and anomalies.
    """

    def __init__(self, sessions: list[ScanSession]) -> None:
        self.sessions = sorted(sessions, key=lambda s: s.start_time)

    def device_timeline(self, bssid: str) -> DeviceTrend:
        """Build a timeline for a specific AP across all sessions.

        Args:
            bssid: The AP's BSSID to track.

        Returns:
            DeviceTrend with temporal data points.
        """
        trend = DeviceTrend(identifier=bssid, label="")

        for session in self.sessions:
            if bssid in session.access_points:
                ap = session.access_points[bssid]
                if not trend.label and ap.ssid:
                    trend.label = ap.ssid
                trend.timestamps.append(ap.last_seen)
                trend.rssi_values.append(ap.rssi)
                trend.channels.append(ap.channel)

        return trend

    def activity_timeline(self, slot_minutes: int = 5) -> list[TimeSlot]:
        """Build an activity timeline showing device counts over time.

        Args:
            slot_minutes: Width of each time slot in minutes.

        Returns:
            List of TimeSlots with activity counts.
        """
        if not self.sessions:
            return []

        # Collect all device sightings with timestamps
        all_ap_times: list[tuple[datetime, str]] = []
        for session in self.sessions:
            for ap in session.access_points.values():
                all_ap_times.append((ap.first_seen, ap.bssid))
                all_ap_times.append((ap.last_seen, ap.bssid))

        if not all_ap_times:
            return []

        all_ap_times.sort(key=lambda x: x[0])
        start = all_ap_times[0][0]
        end = all_ap_times[-1][0]

        slots = []
        current = start
        delta = timedelta(minutes=slot_minutes)
        prev_aps: set[str] = set()

        while current < end:
            slot_end = current + delta
            # APs active in this slot
            active_aps = set()
            active_clients = set()

            for session in self.sessions:
                for bssid, ap in session.access_points.items():
                    if ap.first_seen <= slot_end and ap.last_seen >= current:
                        active_aps.add(bssid)
                for mac, cl in session.clients.items():
                    if cl.first_seen <= slot_end and cl.last_seen >= current:
                        active_clients.add(mac)

            new_aps = len(active_aps - prev_aps)
            lost_aps = len(prev_aps - active_aps)

            slots.append(TimeSlot(
                start=current,
                end=slot_end,
                ap_count=len(active_aps),
                client_count=len(active_clients),
                new_aps=new_aps,
                lost_aps=lost_aps,
            ))

            prev_aps = active_aps
            current = slot_end

        return slots

    def first_seen_distribution(self) -> dict[str, datetime]:
        """Get the first-seen time for each AP across all sessions."""
        first_seen: dict[str, datetime] = {}
        for session in self.sessions:
            for bssid, ap in session.access_points.items():
                if bssid not in first_seen or ap.first_seen < first_seen[bssid]:
                    first_seen[bssid] = ap.first_seen
        return first_seen

    def channel_usage_over_time(self) -> list[dict[int, int]]:
        """Track channel utilization across sessions.

        Returns:
            List of dicts (one per session), each mapping channel -> AP count.
        """
        result = []
        for session in self.sessions:
            channel_counts: dict[int, int] = Counter()
            for ap in session.access_points.values():
                channel_counts[ap.channel] += 1
            result.append(dict(channel_counts))
        return result

    def signal_stability(self, bssid: str) -> Optional[dict]:
        """Analyze signal stability for an AP across sessions.

        Returns dict with min, max, avg, stddev of RSSI, or None if not found.
        """
        trend = self.device_timeline(bssid)
        if not trend.rssi_values:
            return None

        import numpy as np
        values = np.array(trend.rssi_values)

        return {
            "bssid": bssid,
            "ssid": trend.label,
            "min_rssi": int(values.min()),
            "max_rssi": int(values.max()),
            "avg_rssi": float(values.mean()),
            "std_rssi": float(values.std()),
            "measurements": len(values),
            "duration": trend.duration,
        }

    def find_anomalies(self) -> list[dict]:
        """Detect anomalous patterns like sudden AP appearances or encryption changes.

        Returns:
            List of anomaly descriptions.
        """
        anomalies = []

        if len(self.sessions) < 2:
            return anomalies

        for i in range(1, len(self.sessions)):
            prev = self.sessions[i - 1]
            curr = self.sessions[i]

            # New APs that weren't in previous session
            for bssid in set(curr.access_points.keys()) - set(prev.access_points.keys()):
                ap = curr.access_points[bssid]
                anomalies.append({
                    "type": "new_ap",
                    "severity": "info",
                    "bssid": bssid,
                    "ssid": ap.ssid,
                    "session": curr.name,
                    "message": f"New AP detected: {ap.ssid or '[Hidden]'} ({bssid})",
                })

            # Encryption downgrades
            for bssid in set(curr.access_points.keys()) & set(prev.access_points.keys()):
                prev_ap = prev.access_points[bssid]
                curr_ap = curr.access_points[bssid]

                enc_order = ["Open", "WEP", "WPA", "WPA2", "WPA3"]
                prev_idx = enc_order.index(prev_ap.encryption.value) if prev_ap.encryption.value in enc_order else -1
                curr_idx = enc_order.index(curr_ap.encryption.value) if curr_ap.encryption.value in enc_order else -1

                if curr_idx < prev_idx:
                    anomalies.append({
                        "type": "encryption_downgrade",
                        "severity": "warning",
                        "bssid": bssid,
                        "ssid": curr_ap.ssid,
                        "message": (
                            f"Encryption downgrade: {prev_ap.encryption.value} -> "
                            f"{curr_ap.encryption.value} on {curr_ap.ssid or bssid}"
                        ),
                    })

                # SSID change (possible evil twin)
                if prev_ap.ssid and curr_ap.ssid and prev_ap.ssid != curr_ap.ssid:
                    anomalies.append({
                        "type": "ssid_change",
                        "severity": "warning",
                        "bssid": bssid,
                        "message": f"SSID changed: '{prev_ap.ssid}' -> '{curr_ap.ssid}' on {bssid}",
                    })

        return anomalies
