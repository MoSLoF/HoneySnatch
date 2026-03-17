"""Bluetooth device data models for BlueScout."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from flyinghoneysnitch.core.models import GeoPosition


@dataclass
class BluetoothDevice:
    """A discovered Bluetooth device."""

    address: str  # BD_ADDR (Bluetooth Device Address)
    device_type: str = "Unknown"  # Classic, BLE, Dual
    rssi: int = -100
    name: str = ""
    device_class: int = 0  # CoD (Class of Device)
    device_class_name: str = ""
    manufacturer: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    position: Optional[GeoPosition] = None
    channels: list[int] = field(default_factory=list)
    packet_count: int = 0

    def update(self, rssi: int, position: Optional[GeoPosition] = None) -> None:
        """Update device with new observation."""
        self.rssi = rssi
        self.last_seen = datetime.now()
        self.packet_count += 1
        if position:
            self.position = position


# Bluetooth Class of Device major categories
COD_MAJOR_CLASSES = {
    0: "Miscellaneous",
    1: "Computer",
    2: "Phone",
    3: "LAN/Network Access Point",
    4: "Audio/Video",
    5: "Peripheral",
    6: "Imaging",
    7: "Wearable",
    8: "Toy",
    9: "Health",
    31: "Uncategorized",
}


def classify_device(cod: int) -> str:
    """Classify a Bluetooth device from its Class of Device value."""
    major = (cod >> 8) & 0x1F
    return COD_MAJOR_CLASSES.get(major, "Unknown")
