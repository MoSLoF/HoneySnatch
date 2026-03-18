"""802.11 packet parser for extracting wireless network information.

Parses beacon frames, probe requests/responses, data frames, and
authentication frames to identify access points and clients.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    Dot11QoS,
    RadioTap,
)
from scapy.packet import Packet

from honeysnatch.core.models import (
    AccessPoint,
    Band,
    Client,
    EncryptionType,
)
from honeysnatch.utils.logger import get_logger

log = get_logger("parser")

# 802.11 frame type/subtype constants
TYPE_MANAGEMENT = 0
TYPE_CONTROL = 1
TYPE_DATA = 2

SUBTYPE_ASSOC_REQ = 0
SUBTYPE_ASSOC_RESP = 1
SUBTYPE_PROBE_REQ = 4
SUBTYPE_PROBE_RESP = 5
SUBTYPE_BEACON = 8
SUBTYPE_AUTH = 11
SUBTYPE_DEAUTH = 12

# Broadcast/multicast MAC patterns
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def parse_packet(packet: Packet) -> Optional[dict]:
    """Parse a raw 802.11 packet and extract relevant information.

    Args:
        packet: A scapy packet (typically sniffed with RadioTap header).

    Returns:
        Dictionary with parsed info and type, or None if not a relevant 802.11 frame.
    """
    if not packet.haslayer(Dot11):
        return None

    dot11 = packet[Dot11]
    frame_type = dot11.type
    frame_subtype = dot11.subtype

    # Extract RadioTap signal info
    rssi = _extract_rssi(packet)
    channel, frequency = _extract_channel(packet)

    if frame_type == TYPE_MANAGEMENT:
        if dot11.haslayer(Dot11Beacon):
            return _parse_beacon(dot11, rssi, channel, frequency)
        elif dot11.haslayer(Dot11ProbeReq):
            return _parse_probe_request(dot11, rssi)
        elif dot11.haslayer(Dot11ProbeResp):
            return _parse_probe_response(dot11, rssi, channel, frequency)
        elif dot11.haslayer(Dot11Auth):
            return _parse_auth(dot11, rssi)
        elif dot11.haslayer(Dot11AssoReq):
            return _parse_association_request(dot11, rssi)

    elif frame_type == TYPE_DATA:
        return _parse_data_frame(dot11, rssi)

    return None


def _parse_beacon(dot11: Dot11, rssi: int, channel: int, frequency: int) -> dict:
    """Parse a beacon frame to extract AP information."""
    bssid = dot11.addr3
    if not bssid:
        return None

    bssid = bssid.lower()
    ssid = ""
    encryption = EncryptionType.OPEN
    cipher = ""
    auth = ""
    rates = []
    wps = False
    country = ""

    # Parse information elements
    elt = dot11[Dot11Beacon].payload
    while isinstance(elt, Dot11Elt):
        elt_id = elt.ID

        if elt_id == 0:  # SSID
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                ssid = ""

        elif elt_id == 3:  # DS Parameter Set (channel)
            if elt.info and len(elt.info) >= 1:
                channel = elt.info[0]

        elif elt_id == 1:  # Supported rates
            rates.extend(_parse_rates(elt.info))

        elif elt_id == 50:  # Extended supported rates
            rates.extend(_parse_rates(elt.info))

        elif elt_id == 7:  # Country
            try:
                country = elt.info[:2].decode("ascii", errors="replace")
            except Exception:
                pass

        elif elt_id == 48:  # RSN (WPA2/WPA3)
            enc, ci, au = _parse_rsn(elt.info)
            encryption = enc
            cipher = ci
            auth = au

        elif elt_id == 221:  # Vendor specific
            if elt.info and len(elt.info) >= 4:
                oui = elt.info[:3]
                if oui == b"\x00\x50\xf2":
                    oui_type = elt.info[3]
                    if oui_type == 1:  # WPA
                        if encryption == EncryptionType.OPEN:
                            encryption = EncryptionType.WPA
                    elif oui_type == 4:  # WPS
                        wps = True

        elt = elt.payload

    # Check for hidden SSID
    hidden = not ssid or ssid == "\x00" * len(ssid) if ssid else True
    if hidden:
        ssid = ""

    # Determine band
    band = _frequency_to_band(frequency) if frequency else _channel_to_band(channel)

    # Check WEP from capability info
    cap = dot11[Dot11Beacon].cap
    if encryption == EncryptionType.OPEN and hasattr(cap, "privacy") and cap.privacy:
        encryption = EncryptionType.WEP

    ap = AccessPoint(
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        frequency=frequency,
        rssi=rssi,
        encryption=encryption,
        cipher=cipher,
        auth=auth,
        band=band,
        hidden=hidden,
        beacon_count=1,
        wps=wps,
        country=country,
        rates=rates,
    )

    return {"type": "beacon", "ap": ap}


def _parse_probe_request(dot11: Dot11, rssi: int) -> dict:
    """Parse a probe request to identify a client and its probed SSIDs."""
    src = dot11.addr2
    if not src or src.lower() == BROADCAST_MAC:
        return None

    ssid = ""
    elt = dot11[Dot11ProbeReq].payload
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0 and elt.info:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                ssid = ""
            break
        elt = elt.payload

    client = Client(
        mac=src.lower(),
        rssi=rssi,
        probe_requests=[ssid] if ssid else [],
    )

    return {"type": "probe_request", "client": client, "ssid": ssid}


def _parse_probe_response(dot11: Dot11, rssi: int, channel: int, frequency: int) -> dict:
    """Parse a probe response (similar to beacon, from AP to specific client)."""
    # Probe responses have similar structure to beacons
    result = _parse_beacon.__wrapped__(dot11, rssi, channel, frequency) if hasattr(_parse_beacon, '__wrapped__') else None

    # Simplified: treat probe response similar to beacon
    bssid = dot11.addr3
    if not bssid:
        return None

    bssid = bssid.lower()
    ssid = ""

    elt = dot11[Dot11ProbeResp].payload
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0 and elt.info:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                ssid = ""
            break
        elt = elt.payload

    band = _frequency_to_band(frequency) if frequency else _channel_to_band(channel)

    ap = AccessPoint(
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        frequency=frequency,
        rssi=rssi,
        band=band,
    )

    # Also track the client that received the response
    dst = dot11.addr1
    client = None
    if dst and dst.lower() != BROADCAST_MAC:
        client = Client(mac=dst.lower(), bssid=bssid, rssi=rssi)

    return {"type": "probe_response", "ap": ap, "client": client}


def _parse_auth(dot11: Dot11, rssi: int) -> dict:
    """Parse an authentication frame."""
    src = dot11.addr2
    dst = dot11.addr1
    bssid = dot11.addr3

    if not src or not bssid:
        return None

    return {
        "type": "auth",
        "src": src.lower(),
        "dst": dst.lower() if dst else None,
        "bssid": bssid.lower(),
        "rssi": rssi,
    }


def _parse_association_request(dot11: Dot11, rssi: int) -> dict:
    """Parse an association request (client -> AP)."""
    client_mac = dot11.addr2
    bssid = dot11.addr3

    if not client_mac or not bssid:
        return None

    ssid = ""
    elt = dot11[Dot11AssoReq].payload
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0 and elt.info:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                ssid = ""
            break
        elt = elt.payload

    client = Client(
        mac=client_mac.lower(),
        bssid=bssid.lower(),
        ssid=ssid,
        rssi=rssi,
    )

    return {"type": "association_request", "client": client}


def _parse_data_frame(dot11: Dot11, rssi: int) -> dict:
    """Parse a data frame to identify communicating devices."""
    # Determine direction from To DS / From DS flags
    to_ds = dot11.FCfield & 0x1
    from_ds = dot11.FCfield & 0x2

    bssid = None
    src = None
    dst = None

    if to_ds and not from_ds:
        # Client -> AP (To DS)
        bssid = dot11.addr1
        src = dot11.addr2
        dst = dot11.addr3
    elif not to_ds and from_ds:
        # AP -> Client (From DS)
        dst = dot11.addr1
        bssid = dot11.addr2
        src = dot11.addr3
    elif to_ds and from_ds:
        # WDS (bridge)
        return None
    else:
        # Ad-hoc / IBSS
        bssid = dot11.addr3
        src = dot11.addr2
        dst = dot11.addr1

    if not src:
        return None

    src = src.lower()
    client = None

    if bssid and src != bssid.lower():
        client = Client(
            mac=src,
            bssid=bssid.lower(),
            rssi=rssi,
            data_count=1,
        )

    return {
        "type": "data",
        "src": src,
        "dst": dst.lower() if dst else None,
        "bssid": bssid.lower() if bssid else None,
        "client": client,
        "rssi": rssi,
    }


def _extract_rssi(packet: Packet) -> int:
    """Extract RSSI/signal strength from RadioTap header."""
    if packet.haslayer(RadioTap):
        rt = packet[RadioTap]
        if hasattr(rt, "dBm_AntSignal"):
            return rt.dBm_AntSignal
        if hasattr(rt, "dBm_AntNoise"):
            return rt.dBm_AntNoise
    return -100  # Default weak signal


def _extract_channel(packet: Packet) -> tuple[int, int]:
    """Extract channel and frequency from RadioTap header.

    Returns:
        Tuple of (channel_number, frequency_mhz).
    """
    channel = 0
    frequency = 0

    if packet.haslayer(RadioTap):
        rt = packet[RadioTap]
        if hasattr(rt, "ChannelFrequency"):
            frequency = rt.ChannelFrequency
            channel = _frequency_to_channel(frequency)

    return channel, frequency


def _parse_rsn(data: bytes) -> tuple[EncryptionType, str, str]:
    """Parse RSN (Robust Security Network) information element.

    Returns:
        Tuple of (encryption_type, cipher_suite, auth_method).
    """
    if len(data) < 2:
        return EncryptionType.UNKNOWN, "", ""

    try:
        # RSN version
        _version = int.from_bytes(data[0:2], "little")

        cipher = ""
        auth = ""
        encryption = EncryptionType.WPA2

        # Group cipher suite
        if len(data) >= 6:
            cipher = _parse_cipher_suite(data[2:6])

        # Pairwise cipher suites
        if len(data) >= 8:
            count = int.from_bytes(data[6:8], "little")
            offset = 8
            pairwise_ciphers = []
            for _ in range(count):
                if offset + 4 <= len(data):
                    pairwise_ciphers.append(_parse_cipher_suite(data[offset:offset + 4]))
                    offset += 4
            if pairwise_ciphers:
                cipher = "/".join(pairwise_ciphers)

        # AKM suites
        if len(data) >= offset + 2:
            count = int.from_bytes(data[offset:offset + 2], "little")
            offset += 2
            akm_suites = []
            for _ in range(count):
                if offset + 4 <= len(data):
                    akm_suites.append(_parse_akm_suite(data[offset:offset + 4]))
                    offset += 4
            if akm_suites:
                auth = "/".join(akm_suites)

            # Check for SAE (WPA3)
            if any("SAE" in a for a in akm_suites):
                encryption = EncryptionType.WPA3
            elif any("802.1X" in a for a in akm_suites):
                encryption = EncryptionType.WPA2_ENTERPRISE

        return encryption, cipher, auth

    except Exception:
        return EncryptionType.WPA2, "", ""


def _parse_cipher_suite(data: bytes) -> str:
    """Parse a cipher suite selector."""
    if len(data) < 4:
        return "Unknown"
    suite_type = data[3]
    return {
        0: "Group",
        1: "WEP-40",
        2: "TKIP",
        4: "CCMP",
        5: "WEP-104",
        6: "BIP-CMAC-128",
        8: "GCMP-128",
        9: "GCMP-256",
        10: "CCMP-256",
    }.get(suite_type, f"Unknown({suite_type})")


def _parse_akm_suite(data: bytes) -> str:
    """Parse an Authentication and Key Management suite selector."""
    if len(data) < 4:
        return "Unknown"
    suite_type = data[3]
    return {
        1: "802.1X",
        2: "PSK",
        3: "FT-802.1X",
        4: "FT-PSK",
        6: "802.1X-SHA256",
        8: "SAE",
        9: "FT-SAE",
        12: "802.1X-Suite-B",
        18: "OWE",
    }.get(suite_type, f"Unknown({suite_type})")


def _parse_rates(data: bytes) -> list[float]:
    """Parse supported rates from an information element."""
    rates = []
    for byte in data:
        rate = (byte & 0x7F) * 0.5  # Rate in Mbps
        if rate > 0:
            rates.append(rate)
    return rates


def _frequency_to_channel(freq: int) -> int:
    """Convert WiFi frequency (MHz) to channel number."""
    if 2412 <= freq <= 2484:
        if freq == 2484:
            return 14
        return (freq - 2407) // 5
    elif 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    elif 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def _channel_to_band(channel: int) -> Band:
    """Determine the band from a channel number."""
    if 1 <= channel <= 14:
        return Band.BAND_2_4GHZ
    elif 36 <= channel <= 177:
        return Band.BAND_5GHZ
    return Band.BAND_2_4GHZ


def _frequency_to_band(freq: int) -> Band:
    """Determine the band from a frequency."""
    if 2400 <= freq <= 2500:
        return Band.BAND_2_4GHZ
    elif 5000 <= freq <= 5900:
        return Band.BAND_5GHZ
    elif 5925 <= freq <= 7125:
        return Band.BAND_6GHZ
    return Band.BAND_2_4GHZ
