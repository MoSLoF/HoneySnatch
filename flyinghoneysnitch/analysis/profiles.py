"""Device profile filtering and classification for HoneyView.

Provides flexible filtering and classification of discovered devices
based on various attributes like vendor, encryption, signal strength, etc.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from flyinghoneysnitch.core.models import AccessPoint, Client, EncryptionType, ScanSession


class FilterOperator(Enum):
    """Comparison operators for profile filters."""

    EQUALS = "eq"
    NOT_EQUALS = "ne"
    CONTAINS = "contains"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    IN = "in"
    NOT_IN = "not_in"


@dataclass
class ProfileFilter:
    """A single filter criterion."""

    field: str
    operator: FilterOperator
    value: object


@dataclass
class DeviceProfile:
    """A named device profile (filter set)."""

    name: str
    description: str = ""
    filters: list[ProfileFilter] = None

    def __post_init__(self):
        if self.filters is None:
            self.filters = []


# Built-in profiles
PROFILE_OPEN_NETWORKS = DeviceProfile(
    name="Open Networks",
    description="Access points with no encryption",
    filters=[ProfileFilter("encryption", FilterOperator.EQUALS, EncryptionType.OPEN)],
)

PROFILE_WEAK_ENCRYPTION = DeviceProfile(
    name="Weak Encryption",
    description="APs using WEP or WPA (not WPA2/WPA3)",
    filters=[ProfileFilter("encryption", FilterOperator.IN, [EncryptionType.WEP, EncryptionType.WPA])],
)

PROFILE_HIDDEN_NETWORKS = DeviceProfile(
    name="Hidden Networks",
    description="Access points with cloaked SSIDs",
    filters=[ProfileFilter("hidden", FilterOperator.EQUALS, True)],
)

PROFILE_WPS_ENABLED = DeviceProfile(
    name="WPS Enabled",
    description="APs with WPS enabled (potential attack vector)",
    filters=[ProfileFilter("wps", FilterOperator.EQUALS, True)],
)

PROFILE_STRONG_SIGNAL = DeviceProfile(
    name="Strong Signal",
    description="Devices with RSSI > -50 dBm",
    filters=[ProfileFilter("rssi", FilterOperator.GREATER_THAN, -50)],
)

BUILTIN_PROFILES = [
    PROFILE_OPEN_NETWORKS,
    PROFILE_WEAK_ENCRYPTION,
    PROFILE_HIDDEN_NETWORKS,
    PROFILE_WPS_ENABLED,
    PROFILE_STRONG_SIGNAL,
]


class ProfileEngine:
    """Applies device profiles (filter sets) to scan data."""

    def __init__(self) -> None:
        self._profiles: dict[str, DeviceProfile] = {
            p.name: p for p in BUILTIN_PROFILES
        }

    def add_profile(self, profile: DeviceProfile) -> None:
        """Register a custom profile."""
        self._profiles[profile.name] = profile

    def get_profile(self, name: str) -> Optional[DeviceProfile]:
        """Get a profile by name."""
        return self._profiles.get(name)

    def list_profiles(self) -> list[DeviceProfile]:
        """List all available profiles."""
        return list(self._profiles.values())

    def filter_aps(
        self,
        aps: list[AccessPoint],
        profile: DeviceProfile,
    ) -> list[AccessPoint]:
        """Filter access points using a device profile.

        Args:
            aps: List of access points to filter.
            profile: The profile to apply.

        Returns:
            List of APs matching all profile filters.
        """
        result = aps
        for f in profile.filters:
            result = [ap for ap in result if _check_filter(ap, f)]
        return result

    def filter_clients(
        self,
        clients: list[Client],
        profile: DeviceProfile,
    ) -> list[Client]:
        """Filter clients using a device profile."""
        result = clients
        for f in profile.filters:
            result = [cl for cl in result if _check_filter(cl, f)]
        return result

    def classify_ap(self, ap: AccessPoint) -> list[str]:
        """Classify an AP against all profiles.

        Returns:
            List of profile names this AP matches.
        """
        matching = []
        for profile in self._profiles.values():
            if all(_check_filter(ap, f) for f in profile.filters):
                matching.append(profile.name)
        return matching

    def security_score(self, ap: AccessPoint) -> int:
        """Calculate a security score for an AP (0-100, higher = more secure).

        Factors:
        - Encryption type (major)
        - WPS status
        - Hidden SSID (minor benefit)
        """
        score = 50  # Base score

        # Encryption (biggest factor)
        enc_scores = {
            EncryptionType.OPEN: -40,
            EncryptionType.WEP: -30,
            EncryptionType.WPA: -10,
            EncryptionType.WPA2: 20,
            EncryptionType.WPA3: 30,
            EncryptionType.WPA2_ENTERPRISE: 35,
            EncryptionType.WPA3_ENTERPRISE: 40,
        }
        score += enc_scores.get(ap.encryption, 0)

        # WPS penalty
        if ap.wps:
            score -= 15

        # Auth method bonus
        if "SAE" in ap.auth:
            score += 10
        elif "802.1X" in ap.auth:
            score += 10

        return max(0, min(100, score))


def _check_filter(obj: object, f: ProfileFilter) -> bool:
    """Check if an object passes a single filter."""
    value = getattr(obj, f.field, None)
    if value is None:
        return False

    if f.operator == FilterOperator.EQUALS:
        return value == f.value
    elif f.operator == FilterOperator.NOT_EQUALS:
        return value != f.value
    elif f.operator == FilterOperator.CONTAINS:
        return f.value in str(value).lower()
    elif f.operator == FilterOperator.GREATER_THAN:
        return value > f.value
    elif f.operator == FilterOperator.LESS_THAN:
        return value < f.value
    elif f.operator == FilterOperator.IN:
        return value in f.value
    elif f.operator == FilterOperator.NOT_IN:
        return value not in f.value

    return False
