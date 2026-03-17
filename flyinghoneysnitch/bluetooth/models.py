"""Bluetooth device data models for BlueScout."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from flyinghoneysnitch.core.models import GeoPosition


class BleAdvType(Enum):
    """BLE advertisement PDU types."""
    ADV_IND = "ADV_IND"             # Connectable undirected
    ADV_DIRECT_IND = "ADV_DIRECT"   # Connectable directed
    ADV_NONCONN_IND = "ADV_NONCONN" # Non-connectable undirected
    ADV_SCAN_IND = "ADV_SCAN"       # Scannable undirected
    SCAN_RSP = "SCAN_RSP"           # Scan response
    UNKNOWN = "Unknown"


class BluetoothDeviceType(Enum):
    """Bluetooth radio type."""
    CLASSIC = "Classic"
    BLE = "BLE"
    DUAL = "Dual"
    UNKNOWN = "Unknown"


# ---------------------------------------------------------------------------
# BLE advertisement data structures
# ---------------------------------------------------------------------------

@dataclass
class BleAdvertisement:
    """Parsed BLE advertisement payload."""

    adv_type: BleAdvType = BleAdvType.UNKNOWN
    flags: int = 0                          # AD type 0x01 flags byte
    local_name: str = ""                    # AD type 0x08 / 0x09
    tx_power: Optional[int] = None          # AD type 0x0A (dBm)
    service_uuids: list[str] = field(default_factory=list)   # 16/32/128-bit
    manufacturer_id: Optional[int] = None   # AD type 0xFF company id
    manufacturer_data: bytes = b""          # AD type 0xFF payload
    service_data: dict[str, bytes] = field(default_factory=dict)  # uuid -> data
    raw_ad: bytes = b""                     # Full AD payload for reference

    # Decoded beacon types (populated by classifier)
    is_ibeacon: bool = False
    is_eddystone: bool = False
    is_airdrop: bool = False
    is_findmy: bool = False
    is_microsoft: bool = False
    beacon_meta: dict = field(default_factory=dict)  # beacon-specific fields

    @property
    def connectable(self) -> bool:
        return self.adv_type in (BleAdvType.ADV_IND, BleAdvType.ADV_DIRECT_IND)

    @property
    def is_random_address_likely(self) -> bool:
        """Flags bit 0 = LE Limited, bit 2 = BR/EDR Not Supported → pure BLE."""
        return bool(self.flags & 0x04)


@dataclass
class BluetoothDevice:
    """A discovered Bluetooth device."""

    address: str                                    # BD_ADDR / BLE random addr
    device_type: BluetoothDeviceType = BluetoothDeviceType.UNKNOWN
    rssi: int = -100
    name: str = ""
    device_class: int = 0                           # CoD (Classic only)
    device_class_name: str = ""
    manufacturer: str = ""                          # OUI vendor
    company_name: str = ""                          # from manufacturer_id
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    position: Optional[GeoPosition] = None
    channels: list[int] = field(default_factory=list)
    packet_count: int = 0
    advertisement: Optional[BleAdvertisement] = None
    rssi_history: list[int] = field(default_factory=list)  # last 20 readings

    # Risk / classification (populated by classifier)
    risk: str = "low"
    risk_reasons: list[str] = field(default_factory=list)

    def update(self, rssi: int, position: Optional[GeoPosition] = None,
               advertisement: Optional[BleAdvertisement] = None) -> None:
        """Update device with a new observation."""
        self.rssi = rssi
        self.last_seen = datetime.now()
        self.packet_count += 1
        self.rssi_history.append(rssi)
        if len(self.rssi_history) > 20:
            self.rssi_history.pop(0)
        if position:
            self.position = position
        if advertisement:
            self.advertisement = advertisement
            if advertisement.local_name and not self.name:
                self.name = advertisement.local_name

    @property
    def rssi_smoothed(self) -> float:
        """Exponential moving average of the last RSSI readings."""
        if not self.rssi_history:
            return float(self.rssi)
        alpha = 0.3
        result = float(self.rssi_history[0])
        for r in self.rssi_history[1:]:
            result = alpha * r + (1 - alpha) * result
        return round(result, 1)

    @property
    def proximity_estimate(self) -> str:
        """Rough proximity estimate from smoothed RSSI (assuming 0 dBm Tx power)."""
        r = self.rssi_smoothed
        if r >= -50:
            return "immediate"   # <1 m
        elif r >= -70:
            return "near"        # 1-3 m
        elif r >= -85:
            return "far"         # 3-10 m
        else:
            return "unknown"     # >10 m or walls


# ---------------------------------------------------------------------------
# Classic Bluetooth Class of Device tables
# ---------------------------------------------------------------------------

COD_MAJOR_CLASSES: dict[int, str] = {
    0:  "Miscellaneous",
    1:  "Computer",
    2:  "Phone",
    3:  "LAN/Network Access Point",
    4:  "Audio/Video",
    5:  "Peripheral",
    6:  "Imaging",
    7:  "Wearable",
    8:  "Toy",
    9:  "Health",
    31: "Uncategorized",
}

COD_MINOR_COMPUTER: dict[int, str] = {
    0: "Uncategorized", 1: "Desktop", 2: "Server", 3: "Laptop",
    4: "Handheld", 5: "Palm", 6: "Wearable",
}

COD_MINOR_PHONE: dict[int, str] = {
    0: "Uncategorized", 1: "Cellular", 2: "Cordless", 3: "Smartphone",
    4: "Wired Modem", 5: "Common ISDN",
}

COD_MINOR_AUDIO: dict[int, str] = {
    0: "Uncategorized", 1: "Headset", 2: "Handsfree", 4: "Microphone",
    5: "Loudspeaker", 6: "Headphones", 7: "Portable Audio", 8: "Car Audio",
    9: "STB", 10: "HiFi", 11: "VCR", 12: "Video Camera", 13: "Camcorder",
    14: "Video Monitor", 20: "Gaming/Toy",
}

# BLE company identifiers (subset of Bluetooth SIG assigned numbers)
COMPANY_IDS: dict[int, str] = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x00E0: "Google",
    0x0075: "Samsung",
    0x000F: "Broadcom",
    0x0010: "Ericsson",
    0x0046: "Motorola",
    0x00D0: "Jabra",
    0x008C: "FitBit",
    0x0059: "Nordic Semiconductor",
    0x02E5: "Espressif",
    0x0499: "Ruuvi Innovations",
    0x0171: "Amazon",
    0x0087: "Garmin",
    0x01D5: "Sony",
    0x0310: "Tile",
    0x0640: "CHIPOLO",
    0x0582: "Suunto",
    0x022B: "Polar Electro",
}


def classify_cod(cod: int) -> tuple[str, str]:
    """Return (major_class, minor_class) from a Classic BT CoD value."""
    major_num = (cod >> 8) & 0x1F
    minor_num  = (cod >> 2) & 0x3F
    major = COD_MAJOR_CLASSES.get(major_num, f"Unknown({major_num})")

    minor_map: dict[int, str] = {}
    if major_num == 1:
        minor_map = COD_MINOR_COMPUTER
    elif major_num == 2:
        minor_map = COD_MINOR_PHONE
    elif major_num == 4:
        minor_map = COD_MINOR_AUDIO

    minor = minor_map.get(minor_num, f"0x{minor_num:02x}")
    return major, minor


def lookup_company(manufacturer_id: int) -> str:
    """Return the company name for a BLE manufacturer ID, or empty string."""
    return COMPANY_IDS.get(manufacturer_id, "")
