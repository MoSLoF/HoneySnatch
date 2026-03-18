"""Bluetooth device classifier and risk assessor for BlueScout.

Classifies Bluetooth devices by:
  - Classic CoD (Class of Device) major/minor categories
  - BLE beacon type (iBeacon, Eddystone, AirDrop, FindMy, SwiftPair)
  - OUI vendor lookup
  - BLE company manufacturer ID
  - Risk heuristics (proximity, tracking beacons, unnamed devices)
"""
from __future__ import annotations

from honeysnatch.bluetooth.models import (
    BluetoothDevice,
    BluetoothDeviceType,
    classify_cod,
    lookup_company,
    COD_MAJOR_CLASSES,
)
from honeysnatch.core.oui_lookup import lookup_vendor
from honeysnatch.utils.logger import get_logger

log = get_logger("bluetooth.classifier")

# Proximity thresholds (dBm, assuming 0 dBm Tx)
_RSSI_IMMEDIATE = -50
_RSSI_NEAR      = -70

# Known tracking beacon company IDs
_TRACKING_COMPANIES = {0x004C, 0x0310, 0x0640}  # Apple, Tile, Chipolo


def classify_bt_device(device: BluetoothDevice) -> BluetoothDevice:
    """Classify and enrich a BluetoothDevice in-place; return it.

    Populates: manufacturer, company_name, device_class_name, risk, risk_reasons.

    Args:
        device: The BluetoothDevice to classify.

    Returns:
        The same device with classification fields populated.
    """
    # --- OUI vendor (works for both Classic and BLE public addresses) ---
    if not device.manufacturer:
        device.manufacturer = lookup_vendor(device.address) or ""

    # --- Classic CoD decoding ---
    if device.device_class and not device.device_class_name:
        major, minor = classify_cod(device.device_class)
        device.device_class_name = f"{major} / {minor}"

    # --- BLE company name from advertisement ---
    adv = device.advertisement
    if adv and adv.manufacturer_id is not None and not device.company_name:
        device.company_name = lookup_company(adv.manufacturer_id) or ""

    # --- Name fallback from advertisement ---
    if adv and adv.local_name and not device.name:
        device.name = adv.local_name

    # --- Risk assessment ---
    risk_reasons: list[str] = []

    # 1. Tracking beacons
    if adv:
        if adv.is_findmy:
            risk_reasons.append("Apple Find My tracking beacon")
        elif adv.is_ibeacon:
            risk_reasons.append("iBeacon (proximity/tracking)")
        if adv.manufacturer_id in _TRACKING_COMPANIES and not adv.is_ibeacon and not adv.is_findmy:
            risk_reasons.append(f"Known tracking company ({device.company_name or hex(adv.manufacturer_id)})")

    # 2. Proximity
    if device.rssi_smoothed >= _RSSI_IMMEDIATE:
        risk_reasons.append(f"Device in immediate range ({device.rssi} dBm)")
    elif device.rssi_smoothed >= _RSSI_NEAR:
        risk_reasons.append(f"Device in near range ({device.rssi} dBm)")

    # 3. Unnamed BLE device — suspicious
    if device.device_type == BluetoothDeviceType.BLE and not device.name:
        if not (adv and (adv.is_ibeacon or adv.is_eddystone)):
            risk_reasons.append("Unnamed BLE device (silent tracker or probe)")

    # 4. Unknown vendor
    if not device.manufacturer and not device.company_name:
        risk_reasons.append("Unknown OUI / manufacturer")

    device.risk_reasons = risk_reasons
    if len(risk_reasons) >= 3:
        device.risk = "high"
    elif len(risk_reasons) >= 1:
        device.risk = "medium"
    else:
        device.risk = "low"

    return device


def summarise_device(device: BluetoothDevice) -> dict:
    """Return a flat dict summary suitable for CLI display or DB storage."""
    adv = device.advertisement
    beacon_type = ""
    if adv and adv.beacon_meta:
        beacon_type = adv.beacon_meta.get("type", "")

    return {
        "address":       device.address,
        "type":          device.device_type.value,
        "name":          device.name,
        "manufacturer":  device.manufacturer,
        "company":       device.company_name,
        "class":         device.device_class_name,
        "beacon_type":   beacon_type,
        "rssi":          device.rssi,
        "rssi_smoothed": device.rssi_smoothed,
        "proximity":     device.proximity_estimate,
        "risk":          device.risk,
        "risk_reasons":  device.risk_reasons,
        "tx_power":      adv.tx_power if adv else None,
        "service_uuids": adv.service_uuids if adv else [],
        "connectable":   adv.connectable if adv else False,
        "first_seen":    device.first_seen.isoformat(),
        "last_seen":     device.last_seen.isoformat(),
        "packet_count":  device.packet_count,
    }
