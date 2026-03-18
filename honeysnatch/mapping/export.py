"""KML/KMZ export for Google Earth integration.

Exports scan data to KML format for visualization in Google Earth,
with network-type-based styling and detailed AP information.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Optional

from honeysnatch.core.models import AccessPoint, GeoPosition, ScanSession
from honeysnatch.utils.logger import get_logger

log = get_logger("export")

# KML style colors by encryption type (aabbggrr format)
KML_COLORS = {
    "Open": "ff0000ff",       # Red
    "WEP": "ff0088ff",        # Orange
    "WPA": "ff00ccff",        # Light orange
    "WPA2": "ff00ff00",       # Green
    "WPA3": "ff00aa00",       # Dark green
    "WPA2-Enterprise": "ff00aa00",
    "WPA3-Enterprise": "ff008800",
    "Unknown": "ff888888",    # Gray
}


def export_kml(
    session: ScanSession,
    output_path: str,
    include_clients: bool = False,
    include_track: bool = True,
    gps_track: Optional[list[GeoPosition]] = None,
) -> str:
    """Export a scan session to KML format.

    Args:
        session: Scan session data.
        output_path: Output file path (.kml or .kmz).
        include_clients: Include client device markers.
        include_track: Include the GPS track line.
        gps_track: GPS track positions.

    Returns:
        Path to the exported file.
    """
    styles = _generate_styles()
    ap_placemarks = _generate_ap_placemarks(session)
    track_placemark = ""

    if include_track and gps_track and len(gps_track) >= 2:
        track_placemark = _generate_track_placemark(gps_track)

    client_placemarks = ""
    if include_clients:
        client_placemarks = _generate_client_placemarks(session)

    kml = f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2"
     xmlns:gx="http://www.google.com/kml/ext/2.2">
  <Document>
    <name>honeysnatch - {_xml_escape(session.name)}</name>
    <description>
      Wireless scan session
      Start: {session.start_time.isoformat()}
      APs: {session.ap_count}, Clients: {session.client_count}
    </description>
{styles}
    <Folder>
      <name>Access Points ({session.ap_count})</name>
{ap_placemarks}
    </Folder>
{f'''    <Folder>
      <name>Clients ({session.client_count})</name>
{client_placemarks}
    </Folder>''' if client_placemarks else ''}
{f'''    <Folder>
      <name>GPS Track</name>
{track_placemark}
    </Folder>''' if track_placemark else ''}
  </Document>
</kml>"""

    # Write KML or KMZ
    if output_path.endswith(".kmz"):
        kml_name = Path(output_path).stem + ".kml"
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(kml_name, kml)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(kml)

    log.info("Exported to %s", output_path)
    return output_path


def _generate_styles() -> str:
    """Generate KML styles for different encryption types."""
    styles = []
    for enc_type, color in KML_COLORS.items():
        style_id = f"style_{enc_type.replace('-', '_').replace(' ', '_')}"
        styles.append(f"""    <Style id="{style_id}">
      <IconStyle>
        <color>{color}</color>
        <scale>1.0</scale>
        <Icon>
          <href>http://maps.google.com/mapfiles/kml/shapes/target.png</href>
        </Icon>
      </IconStyle>
      <LabelStyle>
        <color>{color}</color>
        <scale>0.8</scale>
      </LabelStyle>
    </Style>""")

    styles.append("""    <Style id="style_track">
      <LineStyle>
        <color>ffff0000</color>
        <width>3</width>
      </LineStyle>
    </Style>""")

    styles.append("""    <Style id="style_client">
      <IconStyle>
        <color>ffffff00</color>
        <scale>0.8</scale>
        <Icon>
          <href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href>
        </Icon>
      </IconStyle>
    </Style>""")

    return "\n".join(styles)


def _generate_ap_placemarks(session: ScanSession) -> str:
    """Generate KML placemarks for access points."""
    placemarks = []
    for ap in session.access_points.values():
        if not ap.position:
            continue

        style_id = f"style_{ap.encryption.value.replace('-', '_').replace(' ', '_')}"
        description = (
            f"BSSID: {ap.bssid}\n"
            f"Channel: {ap.channel} ({ap.band.value})\n"
            f"Encryption: {ap.encryption.value}\n"
            f"Cipher: {ap.cipher}\n"
            f"Signal: {ap.rssi} dBm (max: {ap.max_rssi} dBm)\n"
            f"Vendor: {ap.vendor}\n"
            f"Clients: {len(ap.clients)}\n"
            f"Beacons: {ap.beacon_count}\n"
            f"Data frames: {ap.data_count}\n"
            f"WPS: {'Yes' if ap.wps else 'No'}\n"
            f"First seen: {ap.first_seen.isoformat()}\n"
            f"Last seen: {ap.last_seen.isoformat()}"
        )

        placemarks.append(f"""      <Placemark>
        <name>{_xml_escape(ap.ssid or '[Hidden]')}</name>
        <description>{_xml_escape(description)}</description>
        <styleUrl>#{style_id}</styleUrl>
        <Point>
          <coordinates>{ap.position.longitude},{ap.position.latitude},0</coordinates>
        </Point>
      </Placemark>""")

    return "\n".join(placemarks)


def _generate_client_placemarks(session: ScanSession) -> str:
    """Generate KML placemarks for client devices."""
    placemarks = []
    for cl in session.clients.values():
        if not cl.position:
            continue

        description = (
            f"MAC: {cl.mac}\n"
            f"Associated AP: {cl.bssid or 'None'}\n"
            f"Signal: {cl.rssi} dBm\n"
            f"Vendor: {cl.vendor}\n"
            f"Probes: {', '.join(cl.probe_requests) if cl.probe_requests else 'None'}"
        )

        placemarks.append(f"""      <Placemark>
        <name>{cl.mac}</name>
        <description>{_xml_escape(description)}</description>
        <styleUrl>#style_client</styleUrl>
        <Point>
          <coordinates>{cl.position.longitude},{cl.position.latitude},0</coordinates>
        </Point>
      </Placemark>""")

    return "\n".join(placemarks)


def _generate_track_placemark(track: list[GeoPosition]) -> str:
    """Generate a KML line string for the GPS track."""
    coords = " ".join(
        f"{p.longitude},{p.latitude},{p.altitude or 0}" for p in track
    )
    return f"""      <Placemark>
        <name>Scan Track</name>
        <styleUrl>#style_track</styleUrl>
        <LineString>
          <tessellate>1</tessellate>
          <coordinates>{coords}</coordinates>
        </LineString>
      </Placemark>"""


def _xml_escape(s: str) -> str:
    """Escape special XML characters."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
