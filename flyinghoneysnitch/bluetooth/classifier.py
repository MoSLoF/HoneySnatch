"""Bluetooth device classification for BlueScout.

Classifies Bluetooth devices by their Class of Device, OUI, and behavior.
"""

from __future__ import annotations

from flyinghoneysnitch.bluetooth.models import BluetoothDevice, COD_MAJOR_CLASSES
from flyinghoneysnitch.core.oui_lookup import lookup_vendor


def classify_bt_device(device: BluetoothDevice) -> dict:
    """Classify a Bluetooth device and enrich its metadata.

    Args:
        device: The BluetoothDevice to classify.

    Returns:
        Dictionary with classification details.
    """
    # OUI vendor lookup
    vendor = lookup_vendor(device.address)

    # Device class interpretation
    class_name = ""
    if device.device_class:
        major = (device.device_class >> 8) & 0x1F
        class_name = COD_MAJOR_CLASSES.get(major, "Unknown")

    # Risk assessment
    risk = "low"
    risk_reasons = []

    if device.device_type == "BLE" and not device.name:
        risk_reasons.append("Unnamed BLE device (potential beacon/tracker)")
    if device.rssi > -40:
        risk_reasons.append("Very strong signal (very close proximity)")

    if risk_reasons:
        risk = "medium"

    return {
        "address": device.address,
        "vendor": vendor,
        "device_type": device.device_type,
        "class_name": class_name or device.device_class_name,
        "name": device.name,
        "risk": risk,
        "risk_reasons": risk_reasons,
    }
