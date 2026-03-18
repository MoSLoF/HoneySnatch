"""Hidden/cloaked network detection for honeysnatch.

Identifies access points that are broadcasting with hidden SSIDs
and attempts to correlate them with probe responses and association
requests to reveal the actual SSID.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from honeysnatch.core.models import AccessPoint
from honeysnatch.utils.logger import get_logger

log = get_logger("detector")


class HiddenNetworkDetector:
    """Detects and tracks hidden/cloaked wireless networks.

    Hidden networks broadcast beacons with empty or null SSIDs.
    Their actual SSID can be revealed by monitoring:
    - Probe responses (AP responding to a directed probe)
    - Association requests (client connecting to the AP)
    """

    def __init__(self) -> None:
        # BSSID -> list of potential SSIDs seen in probe responses/associations
        self._hidden_aps: dict[str, set[str]] = {}
        # BSSID -> resolved SSID
        self._resolved: dict[str, str] = {}

    def check_beacon(self, ap: AccessPoint) -> bool:
        """Check if a beacon frame indicates a hidden network.

        Args:
            ap: The access point parsed from a beacon frame.

        Returns:
            True if the AP has a hidden SSID.
        """
        if ap.is_hidden:
            if ap.bssid not in self._hidden_aps:
                self._hidden_aps[ap.bssid] = set()
                log.info("Hidden AP detected: %s (channel %d)", ap.bssid, ap.channel)

            # Check if we've already resolved this one
            if ap.bssid in self._resolved:
                ap.ssid = self._resolved[ap.bssid]
                ap.hidden = True
                return True

            return True
        return False

    def process_probe_response(self, bssid: str, ssid: str) -> Optional[str]:
        """Process a probe response that might reveal a hidden SSID.

        Args:
            bssid: The AP's BSSID.
            ssid: The SSID from the probe response.

        Returns:
            The revealed SSID if this resolves a hidden network.
        """
        if not ssid or bssid not in self._hidden_aps:
            return None

        self._hidden_aps[bssid].add(ssid)

        if bssid not in self._resolved:
            self._resolved[bssid] = ssid
            log.info("Hidden SSID revealed: %s -> '%s' (via probe response)", bssid, ssid)
            return ssid

        return None

    def process_association(self, bssid: str, ssid: str) -> Optional[str]:
        """Process an association request that might reveal a hidden SSID.

        Args:
            bssid: The AP's BSSID.
            ssid: The SSID from the association request.

        Returns:
            The revealed SSID if this resolves a hidden network.
        """
        if not ssid or bssid not in self._hidden_aps:
            return None

        self._hidden_aps[bssid].add(ssid)

        if bssid not in self._resolved:
            self._resolved[bssid] = ssid
            log.info("Hidden SSID revealed: %s -> '%s' (via association)", bssid, ssid)
            return ssid

        return None

    @property
    def hidden_count(self) -> int:
        """Number of hidden APs detected."""
        return len(self._hidden_aps)

    @property
    def resolved_count(self) -> int:
        """Number of hidden APs whose SSIDs have been resolved."""
        return len(self._resolved)

    def get_candidates(self, bssid: str) -> list[str]:
        """Get all candidate SSIDs seen for a hidden AP."""
        return sorted(self._hidden_aps.get(bssid, set()))

    def reset(self) -> None:
        """Clear all tracking state."""
        self._hidden_aps.clear()
        self._resolved.clear()
