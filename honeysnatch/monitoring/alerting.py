"""Alert engine for SentryWeb continuous monitoring.

Processes scan events and generates security alerts based on
configurable rules for rogue APs, unauthorized devices, and policy violations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from honeysnatch.core.models import AccessPoint, Client, ScanEvent
from honeysnatch.utils.logger import get_logger

log = get_logger("alerting")


class AlertEngine:
    """Processes scan events and generates security alerts.

    Monitors for:
    - Rogue/unauthorized access points
    - New unknown client devices
    - Encryption downgrades
    - Evil twin attacks
    - Policy violations
    """

    def __init__(
        self,
        authorized_bssids: Optional[set[str]] = None,
        authorized_ssids: Optional[set[str]] = None,
        alert_on_rogue: bool = True,
        alert_on_new_client: bool = False,
        alert_on_open: bool = True,
    ) -> None:
        self.authorized_bssids = authorized_bssids or set()
        self.authorized_ssids = authorized_ssids or set()
        self.alert_on_rogue = alert_on_rogue
        self.alert_on_new_client = alert_on_new_client
        self.alert_on_open = alert_on_open

        self._known_aps: dict[str, dict] = {}  # bssid -> {ssid, encryption, ...}
        self._known_clients: set[str] = set()
        self._alerts: list[dict] = []

    @property
    def alert_count(self) -> int:
        return len(self._alerts)

    def get_alerts(self) -> list[dict]:
        """Get all generated alerts."""
        return self._alerts.copy()

    def process_event(self, event: ScanEvent) -> list[dict]:
        """Process a scan event and return any generated alerts.

        Args:
            event: The scan event to process.

        Returns:
            List of alert dictionaries generated from this event.
        """
        new_alerts = []

        if event.event_type == "ap_found" and event.ap:
            new_alerts.extend(self._check_ap(event.ap))
        elif event.event_type == "ap_updated" and event.ap:
            new_alerts.extend(self._check_ap_change(event.ap))
        elif event.event_type == "client_found" and event.client:
            new_alerts.extend(self._check_client(event.client))
        elif event.event_type == "cell_tower_found" and event.data:
            new_alerts.append({
                "type": "cell_tower_found",
                "severity": "info",
                "message": (
                    f"Cell tower: {event.data.get('technology', '?')} "
                    f"CID={event.data.get('cell_id', '?')} "
                    f"{event.data.get('operator', 'Unknown')}"
                ),
                "timestamp": datetime.now().isoformat(),
            })
        elif event.event_type == "rogue_tower_detected" and event.data:
            new_alerts.append({
                "type": "rogue_tower",
                "severity": event.data.get("severity", "critical"),
                "message": event.data.get("message", "Rogue tower detected"),
                "timestamp": datetime.now().isoformat(),
            })

        self._alerts.extend(new_alerts)
        return new_alerts

    def _check_ap(self, ap: AccessPoint) -> list[dict]:
        """Check a newly discovered AP against authorization rules."""
        alerts = []

        # Rogue AP detection
        if self.alert_on_rogue and self.authorized_bssids:
            if ap.bssid not in self.authorized_bssids:
                severity = "critical" if ap.ssid in self.authorized_ssids else "warning"
                alerts.append({
                    "type": "rogue_ap",
                    "severity": severity,
                    "message": (
                        f"Unauthorized AP detected: {ap.ssid or '[Hidden]'} "
                        f"({ap.bssid}) on channel {ap.channel}"
                    ),
                    "bssid": ap.bssid,
                    "ssid": ap.ssid,
                    "timestamp": datetime.now().isoformat(),
                })

                # Check for evil twin (unauthorized AP using authorized SSID)
                if ap.ssid in self.authorized_ssids:
                    alerts.append({
                        "type": "evil_twin",
                        "severity": "critical",
                        "message": (
                            f"Potential evil twin: Unauthorized AP using known SSID "
                            f"'{ap.ssid}' ({ap.bssid})"
                        ),
                        "bssid": ap.bssid,
                        "ssid": ap.ssid,
                        "timestamp": datetime.now().isoformat(),
                    })

        # Open network alert
        if self.alert_on_open and ap.encryption.value == "Open":
            alerts.append({
                "type": "open_network",
                "severity": "warning",
                "message": f"Open network detected: {ap.ssid or '[Hidden]'} ({ap.bssid})",
                "bssid": ap.bssid,
                "ssid": ap.ssid,
                "timestamp": datetime.now().isoformat(),
            })

        # Track AP
        self._known_aps[ap.bssid] = {
            "ssid": ap.ssid,
            "encryption": ap.encryption.value,
            "channel": ap.channel,
        }

        return alerts

    def _check_ap_change(self, ap: AccessPoint) -> list[dict]:
        """Check for suspicious AP changes (encryption downgrade, SSID change)."""
        alerts = []

        if ap.bssid not in self._known_aps:
            return self._check_ap(ap)

        prev = self._known_aps[ap.bssid]

        # Encryption downgrade
        enc_order = {"Open": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
        prev_level = enc_order.get(prev["encryption"], -1)
        curr_level = enc_order.get(ap.encryption.value, -1)

        if curr_level < prev_level and prev_level >= 0:
            alerts.append({
                "type": "encryption_downgrade",
                "severity": "critical",
                "message": (
                    f"Encryption downgrade on {ap.ssid or ap.bssid}: "
                    f"{prev['encryption']} -> {ap.encryption.value}"
                ),
                "bssid": ap.bssid,
                "timestamp": datetime.now().isoformat(),
            })

        # SSID change
        if prev["ssid"] and ap.ssid and prev["ssid"] != ap.ssid:
            alerts.append({
                "type": "ssid_change",
                "severity": "warning",
                "message": (
                    f"SSID changed on {ap.bssid}: '{prev['ssid']}' -> '{ap.ssid}'"
                ),
                "bssid": ap.bssid,
                "timestamp": datetime.now().isoformat(),
            })

        # Update tracking
        self._known_aps[ap.bssid] = {
            "ssid": ap.ssid,
            "encryption": ap.encryption.value,
            "channel": ap.channel,
        }

        return alerts

    def _check_client(self, client: Client) -> list[dict]:
        """Check a newly discovered client."""
        alerts = []

        if self.alert_on_new_client and client.mac not in self._known_clients:
            alerts.append({
                "type": "new_client",
                "severity": "info",
                "message": (
                    f"New client: {client.mac} "
                    f"({client.vendor or 'Unknown vendor'})"
                    f"{f' -> {client.bssid}' if client.bssid else ''}"
                ),
                "mac": client.mac,
                "timestamp": datetime.now().isoformat(),
            })

        self._known_clients.add(client.mac)
        return alerts
