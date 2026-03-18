"""BLE advertisement parser for BlueScout.

Parses raw AD (Advertising Data) payloads from BLE packets into
structured BleAdvertisement objects.  Handles:

  - AD type 0x01  Flags
  - AD type 0x02/0x03  16-bit UUIDs
  - AD type 0x04/0x05  32-bit UUIDs
  - AD type 0x06/0x07  128-bit UUIDs
  - AD type 0x08/0x09  Shortened / Complete Local Name
  - AD type 0x0A  TX Power Level
  - AD type 0x16  Service Data (16-bit UUID)
  - AD type 0xFF  Manufacturer Specific Data

Beacon-specific decoders:
  - Apple iBeacon  (mfr id 0x004C, subtype 0x02)
  - Eddystone-URL / Eddystone-UID / Eddystone-TLM  (SVC UUID 0xFEAA)
  - Apple AirDrop  (mfr id 0x004C, subtype 0x05)
  - Apple Find My  (mfr id 0x004C, subtype 0x12)
  - Microsoft Swift Pair  (mfr id 0x0006, subtype 0x03)
"""
from __future__ import annotations

import struct
import uuid as _uuid_mod
from typing import Optional

from honeysnatch.bluetooth.models import (
    BleAdvertisement,
    BleAdvType,
    lookup_company,
)
from honeysnatch.utils.logger import get_logger

log = get_logger("bluetooth.ble_parser")

# Eddystone service UUID
_EDDYSTONE_UUID = "feaa"

# Eddystone-URL scheme map
_EDDYSTONE_URL_SCHEMES = {
    0x00: "http://www.",
    0x01: "https://www.",
    0x02: "http://",
    0x03: "https://",
}

_EDDYSTONE_URL_EXPANSIONS = {
    0x00: ".com/",  0x01: ".org/",  0x02: ".edu/",
    0x03: ".net/",  0x04: ".info/", 0x05: ".biz/",
    0x06: ".gov/",  0x07: ".com",   0x08: ".org",
    0x09: ".edu",   0x0A: ".net",   0x0B: ".info",
    0x0C: ".biz",   0x0D: ".gov",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_ble_advertisement(raw_ad: bytes,
                             adv_type: BleAdvType = BleAdvType.UNKNOWN,
                             ) -> BleAdvertisement:
    """Parse raw BLE advertisement bytes into a BleAdvertisement.

    Args:
        raw_ad:   The complete AD payload (everything after the BLE header).
        adv_type: PDU type if known.

    Returns:
        Populated BleAdvertisement object.
    """
    adv = BleAdvertisement(adv_type=adv_type, raw_ad=raw_ad)
    _parse_ad_structures(raw_ad, adv)
    _decode_beacons(adv)
    return adv


# ---------------------------------------------------------------------------
# AD structure parser
# ---------------------------------------------------------------------------

def _parse_ad_structures(data: bytes, adv: BleAdvertisement) -> None:
    """Walk the AD structure list and populate *adv* in-place."""
    offset = 0
    while offset < len(data):
        if offset + 1 > len(data):
            break
        length = data[offset]
        offset += 1
        if length == 0:
            continue
        if offset + length > len(data):
            log.debug("Truncated AD structure at offset %d", offset)
            break

        ad_type = data[offset]
        payload = data[offset + 1: offset + length]
        offset += length

        try:
            _handle_ad_type(ad_type, payload, adv)
        except Exception as exc:
            log.debug("AD type 0x%02x parse error: %s", ad_type, exc)


def _handle_ad_type(ad_type: int, payload: bytes, adv: BleAdvertisement) -> None:
    """Dispatch a single AD type / payload pair."""
    if ad_type == 0x01:
        # Flags
        if payload:
            adv.flags = payload[0]

    elif ad_type in (0x02, 0x03):
        # 16-bit UUID list
        for i in range(0, len(payload) - 1, 2):
            uid = struct.unpack_from("<H", payload, i)[0]
            adv.service_uuids.append(f"{uid:04x}")

    elif ad_type in (0x04, 0x05):
        # 32-bit UUID list
        for i in range(0, len(payload) - 3, 4):
            uid = struct.unpack_from("<I", payload, i)[0]
            adv.service_uuids.append(f"{uid:08x}")

    elif ad_type in (0x06, 0x07):
        # 128-bit UUID list
        for i in range(0, len(payload) - 15, 16):
            uid_bytes = bytes(reversed(payload[i:i + 16]))
            adv.service_uuids.append(str(_uuid_mod.UUID(bytes=uid_bytes)))

    elif ad_type == 0x08:
        # Shortened Local Name
        if not adv.local_name:
            adv.local_name = payload.decode("utf-8", errors="replace")

    elif ad_type == 0x09:
        # Complete Local Name (overrides shortened)
        adv.local_name = payload.decode("utf-8", errors="replace")

    elif ad_type == 0x0A:
        # TX Power Level (signed byte)
        if payload:
            adv.tx_power = struct.unpack_from("b", payload)[0]

    elif ad_type == 0x16:
        # Service Data — 16-bit UUID
        if len(payload) >= 2:
            svc_uuid = f"{struct.unpack_from('<H', payload)[0]:04x}"
            adv.service_data[svc_uuid] = payload[2:]

    elif ad_type == 0xFF:
        # Manufacturer Specific Data
        if len(payload) >= 2:
            adv.manufacturer_id = struct.unpack_from("<H", payload)[0]
            adv.manufacturer_data = payload[2:]
            adv.company_name = lookup_company(adv.manufacturer_id)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Beacon decoders
# ---------------------------------------------------------------------------

def _decode_beacons(adv: BleAdvertisement) -> None:
    """Attempt to identify and decode known beacon formats."""
    if adv.manufacturer_id == 0x004C and adv.manufacturer_data:
        _try_apple(adv)
    if adv.manufacturer_id == 0x0006 and adv.manufacturer_data:
        _try_microsoft(adv)
    if _EDDYSTONE_UUID in adv.service_uuids and _EDDYSTONE_UUID in adv.service_data:
        _try_eddystone(adv, adv.service_data[_EDDYSTONE_UUID])


def _try_apple(adv: BleAdvertisement) -> None:
    """Decode Apple BLE subtypes from manufacturer data."""
    data = adv.manufacturer_data
    if len(data) < 2:
        return
    subtype = data[0]
    length = data[1]

    if subtype == 0x02 and length == 0x15 and len(data) >= 23:
        # iBeacon: subtype(1) len(1) uuid(16) major(2) minor(2) power(1)
        adv.is_ibeacon = True
        beacon_uuid = str(_uuid_mod.UUID(bytes=data[2:18]))
        major = struct.unpack_from(">H", data, 18)[0]
        minor = struct.unpack_from(">H", data, 20)[0]
        tx_power = struct.unpack_from("b", data, 22)[0]
        adv.beacon_meta = {
            "type": "iBeacon",
            "uuid": beacon_uuid,
            "major": major,
            "minor": minor,
            "tx_power": tx_power,
        }
        log.debug("iBeacon: uuid=%s major=%d minor=%d", beacon_uuid, major, minor)

    elif subtype == 0x05:
        # AirDrop
        adv.is_airdrop = True
        adv.beacon_meta = {"type": "AirDrop"}

    elif subtype == 0x12 and len(data) >= 3:
        # Find My
        adv.is_findmy = True
        status = data[2] if len(data) > 2 else 0
        adv.beacon_meta = {"type": "FindMy", "status": status}

    elif subtype == 0x10:
        # Nearby (AirPlay / Continuity)
        adv.beacon_meta = {"type": "AppleNearby", "subtype": hex(subtype)}

    elif subtype == 0x0F:
        # AirPods
        adv.beacon_meta = {"type": "AirPods"}

    else:
        adv.beacon_meta = {"type": "Apple", "subtype": hex(subtype)}


def _try_microsoft(adv: BleAdvertisement) -> None:
    """Decode Microsoft Swift Pair / CDP beacons."""
    data = adv.manufacturer_data
    if not data:
        return
    subtype = data[0]
    if subtype == 0x03:
        # Swift Pair
        adv.is_microsoft = True
        adv.beacon_meta = {"type": "SwiftPair", "subtype": hex(subtype)}
    elif subtype == 0x01:
        adv.is_microsoft = True
        adv.beacon_meta = {"type": "MicrosoftCDP"}
    else:
        adv.is_microsoft = True
        adv.beacon_meta = {"type": "Microsoft", "subtype": hex(subtype)}


def _try_eddystone(adv: BleAdvertisement, payload: bytes) -> None:
    """Decode Eddystone frame types from service data payload."""
    if len(payload) < 1:
        return
    adv.is_eddystone = True
    frame_type = payload[0]

    if frame_type == 0x00 and len(payload) >= 18:
        # Eddystone-UID
        tx_power = struct.unpack_from("b", payload, 1)[0]
        namespace = payload[2:12].hex()
        instance = payload[12:18].hex()
        adv.beacon_meta = {
            "type": "Eddystone-UID",
            "tx_power": tx_power,
            "namespace": namespace,
            "instance": instance,
        }

    elif frame_type == 0x10 and len(payload) >= 4:
        # Eddystone-URL
        tx_power = struct.unpack_from("b", payload, 1)[0]
        scheme = _EDDYSTONE_URL_SCHEMES.get(payload[2], "?://")
        url_body = ""
        for byte in payload[3:]:
            url_body += _EDDYSTONE_URL_EXPANSIONS.get(byte, chr(byte))
        adv.beacon_meta = {
            "type": "Eddystone-URL",
            "tx_power": tx_power,
            "url": scheme + url_body,
        }

    elif frame_type == 0x20 and len(payload) >= 14:
        # Eddystone-TLM (unencrypted)
        version = payload[1]
        vbatt = struct.unpack_from(">H", payload, 2)[0]
        temp_raw = struct.unpack_from(">H", payload, 4)[0]
        temp_c = temp_raw / 256.0
        adv_cnt = struct.unpack_from(">I", payload, 6)[0]
        sec_cnt = struct.unpack_from(">I", payload, 10)[0]
        adv.beacon_meta = {
            "type": "Eddystone-TLM",
            "version": version,
            "battery_mv": vbatt,
            "temperature_c": round(temp_c, 2),
            "adv_count": adv_cnt,
            "uptime_sec": sec_cnt,
        }

    else:
        adv.beacon_meta = {"type": "Eddystone", "frame_type": hex(frame_type)}
