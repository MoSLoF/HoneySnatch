"""GIS utilities for coordinate transforms and distance calculations.

Provides geographic calculations needed for RF mapping and device positioning.
"""

from __future__ import annotations

import math
from typing import Optional

from flyinghoneysnitch.core.models import GeoPosition

# Earth radius in meters
EARTH_RADIUS_M = 6371000.0


def haversine_distance(pos1: GeoPosition, pos2: GeoPosition) -> float:
    """Calculate the great-circle distance between two positions in meters.

    Uses the Haversine formula for accuracy on a spherical Earth model.
    """
    lat1, lon1 = math.radians(pos1.latitude), math.radians(pos1.longitude)
    lat2, lon2 = math.radians(pos2.latitude), math.radians(pos2.longitude)

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))

    return EARTH_RADIUS_M * c


def bearing(pos1: GeoPosition, pos2: GeoPosition) -> float:
    """Calculate initial bearing from pos1 to pos2 in degrees (0-360)."""
    lat1, lon1 = math.radians(pos1.latitude), math.radians(pos1.longitude)
    lat2, lon2 = math.radians(pos2.latitude), math.radians(pos2.longitude)

    dlon = lon2 - lon1
    x = math.sin(dlon) * math.cos(lat2)
    y = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(lat2) * math.cos(dlon)

    initial_bearing = math.degrees(math.atan2(x, y))
    return (initial_bearing + 360) % 360


def destination_point(origin: GeoPosition, bearing_deg: float, distance_m: float) -> GeoPosition:
    """Calculate the destination point given start, bearing, and distance.

    Args:
        origin: Starting position.
        bearing_deg: Bearing in degrees (0 = North).
        distance_m: Distance in meters.

    Returns:
        The destination GeoPosition.
    """
    lat1 = math.radians(origin.latitude)
    lon1 = math.radians(origin.longitude)
    bearing_rad = math.radians(bearing_deg)
    d = distance_m / EARTH_RADIUS_M

    lat2 = math.asin(
        math.sin(lat1) * math.cos(d) + math.cos(lat1) * math.sin(d) * math.cos(bearing_rad)
    )
    lon2 = lon1 + math.atan2(
        math.sin(bearing_rad) * math.sin(d) * math.cos(lat1),
        math.cos(d) - math.sin(lat1) * math.sin(lat2),
    )

    return GeoPosition(
        latitude=math.degrees(lat2),
        longitude=math.degrees(lon2),
        source=origin.source,
    )


def bounding_box(
    positions: list[GeoPosition],
    padding_m: float = 100.0,
) -> tuple[float, float, float, float]:
    """Calculate a bounding box around a set of positions.

    Args:
        positions: List of positions to bound.
        padding_m: Padding in meters around the extremes.

    Returns:
        Tuple of (south_lat, west_lon, north_lat, east_lon).
    """
    if not positions:
        return (0, 0, 0, 0)

    lats = [p.latitude for p in positions]
    lons = [p.longitude for p in positions]

    # Approximate padding in degrees
    lat_pad = padding_m / 111320.0  # ~111km per degree latitude
    avg_lat = sum(lats) / len(lats)
    lon_pad = padding_m / (111320.0 * math.cos(math.radians(avg_lat)))

    return (
        min(lats) - lat_pad,
        min(lons) - lon_pad,
        max(lats) + lat_pad,
        max(lons) + lon_pad,
    )


def center_point(positions: list[GeoPosition]) -> Optional[GeoPosition]:
    """Calculate the geographic center of a set of positions."""
    if not positions:
        return None

    avg_lat = sum(p.latitude for p in positions) / len(positions)
    avg_lon = sum(p.longitude for p in positions) / len(positions)

    return GeoPosition(latitude=avg_lat, longitude=avg_lon, source="calculated")


def rssi_to_distance_m(rssi: int, tx_power: int = -30, path_loss_exponent: float = 3.0) -> float:
    """Estimate distance from RSSI using the log-distance path loss model.

    Args:
        rssi: Received signal strength in dBm.
        tx_power: Transmit power at 1 meter in dBm (default -30 for typical AP).
        path_loss_exponent: Environment factor (2=free space, 3=indoor, 4=obstructed).

    Returns:
        Estimated distance in meters.
    """
    if rssi >= tx_power:
        return 1.0
    return 10 ** ((tx_power - rssi) / (10 * path_loss_exponent))
