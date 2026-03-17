"""Data models for wireless device discovery.

Core data structures representing access points, clients, networks,
and scan sessions used throughout FlyingHoneySnitch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class EncryptionType(Enum):
    """Wireless encryption types."""

    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA2_ENTERPRISE = "WPA2-Enterprise"
    WPA3_ENTERPRISE = "WPA3-Enterprise"
    UNKNOWN = "Unknown"


class DeviceType(Enum):
    """Wireless device classification."""

    ACCESS_POINT = "AP"
    CLIENT = "Client"
    AD_HOC = "Ad-Hoc"
    MONITOR = "Monitor"
    UNKNOWN = "Unknown"


class Band(Enum):
    """WiFi frequency bands."""

    BAND_2_4GHZ = "2.4 GHz"
    BAND_5GHZ = "5 GHz"
    BAND_6GHZ = "6 GHz"


@dataclass
class GeoPosition:
    """Geographic position from GPS or indoor positioning."""

    latitude: float
    longitude: float
    altitude: Optional[float] = None
    accuracy: Optional[float] = None
    source: str = "gps"  # gps, imu, manual
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AccessPoint:
    """Discovered wireless access point."""

    bssid: str  # MAC address
    ssid: str = ""
    channel: int = 0
    frequency: int = 0  # MHz
    rssi: int = -100  # dBm
    encryption: EncryptionType = EncryptionType.UNKNOWN
    cipher: str = ""
    auth: str = ""
    band: Band = Band.BAND_2_4GHZ
    vendor: str = ""
    hidden: bool = False
    beacon_count: int = 0
    data_count: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    position: Optional[GeoPosition] = None
    max_rssi: int = -100
    max_rssi_position: Optional[GeoPosition] = None
    clients: list[str] = field(default_factory=list)  # Client MAC addresses
    rates: list[float] = field(default_factory=list)  # Supported rates in Mbps
    wps: bool = False
    country: str = ""

    @property
    def is_hidden(self) -> bool:
        """Return True if the AP has a hidden or empty SSID."""
        return self.hidden or not self.ssid

    def update_rssi(self, rssi: int, position: Optional[GeoPosition] = None) -> None:
        """Update signal strength, tracking the maximum."""
        self.rssi = rssi
        self.last_seen = datetime.now()
        if rssi > self.max_rssi:
            self.max_rssi = rssi
            if position:
                self.max_rssi_position = position

    def age_seconds(self) -> float:
        """Seconds since last seen."""
        return (datetime.now() - self.last_seen).total_seconds()


@dataclass
class Client:
    """Discovered wireless client station."""

    mac: str  # MAC address
    bssid: Optional[str] = None  # Associated AP BSSID
    ssid: Optional[str] = None  # Probed or associated SSID
    rssi: int = -100
    vendor: str = ""
    device_type: DeviceType = DeviceType.CLIENT
    probe_requests: list[str] = field(default_factory=list)  # SSIDs probed
    data_count: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    position: Optional[GeoPosition] = None

    @property
    def is_associated(self) -> bool:
        """Return True if the client is associated with an access point."""
        return self.bssid is not None

    def add_probe(self, ssid: str) -> None:
        """Record a probe request SSID."""
        if ssid and ssid not in self.probe_requests:
            self.probe_requests.append(ssid)


@dataclass
class ScanSession:
    """A wireless scanning session."""

    session_id: str
    name: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    interface: str = ""
    channels: list[int] = field(default_factory=list)
    access_points: dict[str, AccessPoint] = field(default_factory=dict)  # bssid -> AP
    clients: dict[str, Client] = field(default_factory=dict)  # mac -> Client
    notes: str = ""
    db_path: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        """Return the elapsed duration of this session in seconds."""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    @property
    def ap_count(self) -> int:
        """Return the number of access points discovered in this session."""
        return len(self.access_points)

    @property
    def client_count(self) -> int:
        """Return the number of clients discovered in this session."""
        return len(self.clients)

    def add_ap(self, ap: AccessPoint) -> None:
        """Add or update an access point in this session."""
        if ap.bssid in self.access_points:
            existing = self.access_points[ap.bssid]
            existing.update_rssi(ap.rssi, ap.position)
            existing.beacon_count += ap.beacon_count
            existing.data_count += ap.data_count
            if ap.ssid and not existing.ssid:
                existing.ssid = ap.ssid
            if ap.encryption != EncryptionType.UNKNOWN:
                existing.encryption = ap.encryption
        else:
            self.access_points[ap.bssid] = ap

    def add_client(self, client: Client) -> None:
        """Add or update a client in this session."""
        if client.mac in self.clients:
            existing = self.clients[client.mac]
            existing.rssi = client.rssi
            existing.last_seen = datetime.now()
            existing.data_count += client.data_count
            if client.bssid:
                existing.bssid = client.bssid
            for ssid in client.probe_requests:
                existing.add_probe(ssid)
        else:
            self.clients[client.mac] = client


@dataclass
class ScanEvent:
    """Event emitted by the scanner for real-time updates."""

    event_type: str  # ap_found, ap_updated, client_found, client_updated, cell_tower_found, rogue_tower_detected, scan_started, scan_stopped
    timestamp: datetime = field(default_factory=datetime.now)
    data: Optional[dict] = None
    ap: Optional[AccessPoint] = None
    client: Optional[Client] = None
    cell_tower: Optional[dict] = None  # CellTower data (dict to avoid circular import)
