"""Map rendering using Folium (Leaflet.js) for interactive visualization.

Generates HTML maps with AP markers, client markers, RF heatmap overlays,
GPS tracks, and signal strength indicators.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import folium
from folium.plugins import HeatMap, MarkerCluster

from honeysnatch.core.models import AccessPoint, GeoPosition, ScanSession
from honeysnatch.mapping.rf_map import RFHeatmapData
from honeysnatch.utils.logger import get_logger

log = get_logger("renderer")

# Encryption-based marker colors
ENC_COLORS = {
    "Open": "red",
    "WEP": "orange",
    "WPA": "orange",
    "WPA2": "green",
    "WPA3": "darkgreen",
    "WPA2-Enterprise": "darkgreen",
    "WPA3-Enterprise": "darkgreen",
    "Unknown": "gray",
}


def render_session_map(
    session: ScanSession,
    gps_track: Optional[list[GeoPosition]] = None,
    heatmap_data: Optional[RFHeatmapData] = None,
    output_path: Optional[str] = None,
    tile_server: str = "OpenStreetMap",
) -> str:
    """Render a full scan session as an interactive Folium map.

    Args:
        session: The scan session with discovered APs and clients.
        gps_track: Optional GPS track to overlay.
        heatmap_data: Optional RF heatmap to overlay.
        output_path: Path to save the HTML map. Auto-generated if None.
        tile_server: Map tile source.

    Returns:
        Path to the generated HTML file.
    """
    # Collect all positions for centering
    positions = []
    for ap in session.access_points.values():
        if ap.position:
            positions.append(ap.position)
    if gps_track:
        positions.extend(gps_track)

    if not positions:
        log.warning("No geo-positioned data to render")
        center = [38.9072, -77.0369]  # Default: Washington DC
        zoom = 10
    else:
        center = [
            sum(p.latitude for p in positions) / len(positions),
            sum(p.longitude for p in positions) / len(positions),
        ]
        zoom = 15

    # Create map
    m = folium.Map(location=center, zoom_start=zoom, tiles=tile_server)

    # Add AP markers
    ap_cluster = MarkerCluster(name="Access Points")
    for ap in session.access_points.values():
        if not ap.position:
            continue

        color = ENC_COLORS.get(ap.encryption.value, "gray")
        popup_html = _ap_popup(ap)

        folium.Marker(
            location=[ap.position.latitude, ap.position.longitude],
            popup=folium.Popup(popup_html, max_width=300),
            tooltip=f"{ap.ssid or '[Hidden]'} ({ap.rssi} dBm)",
            icon=folium.Icon(color=color, icon="wifi", prefix="fa"),
        ).add_to(ap_cluster)

    ap_cluster.add_to(m)

    # Add GPS track
    if gps_track and len(gps_track) >= 2:
        track_coords = [[p.latitude, p.longitude] for p in gps_track]
        folium.PolyLine(
            track_coords,
            weight=3,
            color="blue",
            opacity=0.7,
            tooltip="GPS Track",
        ).add_to(m)

    # Add RF heatmap overlay
    if heatmap_data is not None:
        _add_heatmap_overlay(m, heatmap_data)

    # Add signal strength heat data (from AP RSSI at positions)
    signal_data = []
    for ap in session.access_points.values():
        if ap.position:
            # Normalize RSSI to 0-1 intensity (stronger = more intense)
            intensity = max(0, (ap.rssi + 100) / 70)
            signal_data.append([ap.position.latitude, ap.position.longitude, intensity])

    if signal_data:
        HeatMap(
            signal_data,
            name="Signal Strength",
            min_opacity=0.3,
            radius=25,
            blur=15,
        ).add_to(m)

    # Layer control
    folium.LayerControl().add_to(m)

    # Save
    if output_path is None:
        output_path = f"fhb_map_{session.session_id}.html"

    m.save(output_path)
    log.info("Map saved to %s", output_path)
    return output_path


def render_ap_detail_map(
    ap: AccessPoint,
    signal_measurements: Optional[list[tuple[GeoPosition, int]]] = None,
    output_path: Optional[str] = None,
) -> str:
    """Render a detail map for a single access point.

    Shows the AP location, signal measurements, and estimated coverage area.
    """
    if not ap.position:
        raise ValueError(f"AP {ap.bssid} has no position data")

    center = [ap.position.latitude, ap.position.longitude]
    m = folium.Map(location=center, zoom_start=18)

    # AP marker
    popup_html = _ap_popup(ap)
    color = ENC_COLORS.get(ap.encryption.value, "gray")
    folium.Marker(
        location=center,
        popup=folium.Popup(popup_html, max_width=300),
        icon=folium.Icon(color=color, icon="wifi", prefix="fa"),
    ).add_to(m)

    # Signal measurement points
    if signal_measurements:
        for pos, rssi in signal_measurements:
            intensity = max(0, (rssi + 100) / 70)
            color_hex = _rssi_color(rssi)
            folium.CircleMarker(
                location=[pos.latitude, pos.longitude],
                radius=5,
                color=color_hex,
                fill=True,
                fill_opacity=0.7,
                popup=f"{rssi} dBm",
            ).add_to(m)

    if output_path is None:
        output_path = f"fhb_ap_{ap.bssid.replace(':', '')}.html"

    m.save(output_path)
    return output_path


def _add_heatmap_overlay(m: folium.Map, data: RFHeatmapData) -> None:
    """Add an RF heatmap overlay to a Folium map."""
    heat_data = []
    for i, lat in enumerate(data.latitudes):
        for j, lon in enumerate(data.longitudes):
            val = data.values[i, j]
            if val > -95:  # Only show significant signal
                intensity = max(0, (val + 100) / 70)
                heat_data.append([float(lat), float(lon), float(intensity)])

    if heat_data:
        HeatMap(
            heat_data,
            name=f"RF Heatmap ({data.bssid or 'All'})",
            min_opacity=0.2,
            radius=20,
            blur=15,
            gradient={0.2: "blue", 0.4: "cyan", 0.6: "lime", 0.8: "yellow", 1.0: "red"},
        ).add_to(m)


def _ap_popup(ap: AccessPoint) -> str:
    """Generate HTML popup content for an access point marker."""
    return f"""
    <div style="font-family: monospace; font-size: 12px;">
        <b>{ap.ssid or '[Hidden]'}</b><br>
        <hr style="margin: 4px 0;">
        <b>BSSID:</b> {ap.bssid}<br>
        <b>Channel:</b> {ap.channel} ({ap.band.value})<br>
        <b>Encryption:</b> {ap.encryption.value}<br>
        <b>Signal:</b> {ap.rssi} dBm (max: {ap.max_rssi} dBm)<br>
        <b>Vendor:</b> {ap.vendor or 'Unknown'}<br>
        <b>Clients:</b> {len(ap.clients)}<br>
        <b>Beacons:</b> {ap.beacon_count}<br>
        <b>WPS:</b> {'Yes' if ap.wps else 'No'}<br>
        <b>First seen:</b> {ap.first_seen:%H:%M:%S}<br>
        <b>Last seen:</b> {ap.last_seen:%H:%M:%S}<br>
    </div>
    """


def _rssi_color(rssi: int) -> str:
    """Map RSSI to a color hex string (red=weak, green=strong)."""
    if rssi >= -50:
        return "#00ff00"  # Strong
    elif rssi >= -60:
        return "#7fff00"
    elif rssi >= -70:
        return "#ffff00"  # Medium
    elif rssi >= -80:
        return "#ff7f00"
    else:
        return "#ff0000"  # Weak
