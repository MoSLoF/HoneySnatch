"""Communication pattern analysis for HoneyView.

Analyzes probe request patterns, client behavior, device fingerprinting,
and network usage patterns to generate actionable intelligence.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from honeysnatch.core.models import AccessPoint, Client, ScanSession
from honeysnatch.utils.logger import get_logger

log = get_logger("patterns")


@dataclass
class ProbeProfile:
    """Probe request behavior profile for a client."""

    mac: str
    vendor: str
    ssids_probed: list[str] = field(default_factory=list)
    probe_count: int = 0
    is_broadcasting: bool = False  # Sending broadcast probes
    associated_bssid: Optional[str] = None

    @property
    def unique_probes(self) -> int:
        return len(set(self.ssids_probed))

    @property
    def is_active_prober(self) -> bool:
        """Client is actively probing for specific networks."""
        return self.unique_probes > 3


@dataclass
class NetworkProfile:
    """Usage profile for a network (SSID)."""

    ssid: str
    bssids: list[str] = field(default_factory=list)
    client_count: int = 0
    total_data_frames: int = 0
    encryption_types: list[str] = field(default_factory=list)
    channels: list[int] = field(default_factory=list)
    probed_by: list[str] = field(default_factory=list)  # Client MACs that probed this SSID

    @property
    def is_multi_ap(self) -> bool:
        """Network has multiple access points (enterprise)."""
        return len(self.bssids) > 1


class PatternAnalyzer:
    """Analyzes communication patterns in scan data."""

    def __init__(self, session: ScanSession) -> None:
        self.session = session

    def analyze_probe_patterns(self) -> list[ProbeProfile]:
        """Analyze probe request patterns for all clients.

        Returns:
            List of ProbeProfiles for each client that sent probe requests.
        """
        profiles = []

        for cl in self.session.clients.values():
            if not cl.probe_requests:
                continue

            profile = ProbeProfile(
                mac=cl.mac,
                vendor=cl.vendor,
                ssids_probed=cl.probe_requests,
                probe_count=len(cl.probe_requests),
                associated_bssid=cl.bssid,
            )
            profiles.append(profile)

        return sorted(profiles, key=lambda p: p.unique_probes, reverse=True)

    def analyze_network_profiles(self) -> list[NetworkProfile]:
        """Build usage profiles for each discovered network.

        Returns:
            List of NetworkProfiles.
        """
        # Group by SSID
        ssid_data: dict[str, NetworkProfile] = {}

        for ap in self.session.access_points.values():
            ssid = ap.ssid or "[Hidden]"
            if ssid not in ssid_data:
                ssid_data[ssid] = NetworkProfile(ssid=ssid)

            profile = ssid_data[ssid]
            profile.bssids.append(ap.bssid)
            profile.total_data_frames += ap.data_count
            profile.channels.append(ap.channel)
            if ap.encryption.value not in profile.encryption_types:
                profile.encryption_types.append(ap.encryption.value)

        # Count clients per network and track probers
        for cl in self.session.clients.values():
            if cl.bssid:
                for ap in self.session.access_points.values():
                    if ap.bssid == cl.bssid and ap.ssid:
                        if ap.ssid in ssid_data:
                            ssid_data[ap.ssid].client_count += 1
                            break

            for ssid in cl.probe_requests:
                if ssid in ssid_data:
                    ssid_data[ssid].probed_by.append(cl.mac)

        return sorted(ssid_data.values(), key=lambda p: p.client_count, reverse=True)

    def find_common_probes(self, min_count: int = 2) -> list[tuple[str, int]]:
        """Find SSIDs that multiple clients are probing for.

        This can indicate popular nearby networks or target networks.

        Args:
            min_count: Minimum number of unique clients probing for the SSID.

        Returns:
            List of (SSID, client_count) tuples.
        """
        ssid_clients: dict[str, set[str]] = defaultdict(set)

        for cl in self.session.clients.values():
            for ssid in cl.probe_requests:
                ssid_clients[ssid].add(cl.mac)

        common = [
            (ssid, len(clients))
            for ssid, clients in ssid_clients.items()
            if len(clients) >= min_count
        ]

        return sorted(common, key=lambda x: x[1], reverse=True)

    def find_potential_evil_twins(self) -> list[dict]:
        """Detect potential evil twin attacks.

        Looks for multiple APs with the same SSID but different BSSIDs,
        especially if they have different encryption levels.

        Returns:
            List of potential evil twin descriptions.
        """
        results = []

        # Group APs by SSID
        ssid_aps: dict[str, list[AccessPoint]] = defaultdict(list)
        for ap in self.session.access_points.values():
            if ap.ssid:
                ssid_aps[ap.ssid].append(ap)

        for ssid, aps in ssid_aps.items():
            if len(aps) < 2:
                continue

            # Check for mixed encryption levels (suspicious)
            enc_types = set(ap.encryption.value for ap in aps)
            if len(enc_types) > 1 and "Open" in enc_types:
                results.append({
                    "ssid": ssid,
                    "aps": [
                        {"bssid": ap.bssid, "encryption": ap.encryption.value,
                         "channel": ap.channel, "rssi": ap.rssi, "vendor": ap.vendor}
                        for ap in aps
                    ],
                    "risk": "high",
                    "reason": "Same SSID with mixed encryption including Open",
                })
            elif len(enc_types) > 1:
                results.append({
                    "ssid": ssid,
                    "aps": [
                        {"bssid": ap.bssid, "encryption": ap.encryption.value,
                         "channel": ap.channel, "rssi": ap.rssi, "vendor": ap.vendor}
                        for ap in aps
                    ],
                    "risk": "medium",
                    "reason": "Same SSID with different encryption types",
                })

        return results

    def client_device_fingerprint(self, mac: str) -> Optional[dict]:
        """Generate a fingerprint for a client device based on its behavior.

        Args:
            mac: Client MAC address.

        Returns:
            Dict with fingerprint data, or None if client not found.
        """
        cl = self.session.clients.get(mac)
        if not cl:
            return None

        return {
            "mac": cl.mac,
            "vendor": cl.vendor,
            "oui": cl.mac[:8],
            "is_randomized": _is_randomized_mac(cl.mac),
            "probe_count": len(cl.probe_requests),
            "unique_probes": len(set(cl.probe_requests)),
            "associated": cl.is_associated,
            "associated_ssid": cl.ssid,
            "associated_bssid": cl.bssid,
            "data_activity": cl.data_count,
            "probe_ssids": cl.probe_requests,
        }

    def encryption_summary(self) -> dict[str, int]:
        """Summarize encryption types across all APs."""
        return dict(Counter(
            ap.encryption.value for ap in self.session.access_points.values()
        ))

    def vendor_summary(self) -> dict[str, int]:
        """Summarize vendor distribution across all APs."""
        return dict(Counter(
            ap.vendor or "Unknown" for ap in self.session.access_points.values()
        ).most_common(20))


def _is_randomized_mac(mac: str) -> bool:
    """Check if a MAC address appears to be locally administered (randomized).

    The second hex digit of the first octet has bit 1 set for locally
    administered addresses (used by iOS/Android for privacy).
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False
