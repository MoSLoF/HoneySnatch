"""Indoor blueprint overlay support for WarrenMap.

Allows users to overlay RF data onto building floor plan images
for indoor wireless mapping and analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import folium

from honeysnatch.utils.logger import get_logger

log = get_logger("blueprint")


@dataclass
class BlueprintConfig:
    """Configuration for a floor plan blueprint overlay."""

    image_path: str
    # Geographic bounds of the image (for geo-referenced overlays)
    south_lat: float = 0.0
    west_lon: float = 0.0
    north_lat: float = 0.0
    east_lon: float = 0.0
    # Pixel dimensions (for non-geo-referenced overlays)
    width_px: int = 0
    height_px: int = 0
    # Scale: meters per pixel (for non-geo-referenced)
    scale_m_per_px: float = 0.1
    opacity: float = 0.7
    name: str = "Floor Plan"


def add_blueprint_overlay(
    m: folium.Map,
    config: BlueprintConfig,
) -> folium.Map:
    """Add a floor plan image overlay to a Folium map.

    The image is geo-referenced using the provided bounds.

    Args:
        m: Existing Folium map to add the overlay to.
        config: Blueprint configuration with image path and bounds.

    Returns:
        The map with the overlay added.
    """
    if not Path(config.image_path).exists():
        log.error("Blueprint image not found: %s", config.image_path)
        return m

    bounds = [
        [config.south_lat, config.west_lon],
        [config.north_lat, config.east_lon],
    ]

    folium.raster_layers.ImageOverlay(
        image=config.image_path,
        bounds=bounds,
        opacity=config.opacity,
        name=config.name,
        interactive=True,
        cross_origin=False,
    ).add_to(m)

    log.info("Blueprint overlay added: %s", config.name)
    return m


def create_indoor_map(
    config: BlueprintConfig,
    output_path: Optional[str] = None,
) -> str:
    """Create a standalone indoor map centered on the blueprint.

    Args:
        config: Blueprint configuration.
        output_path: Output HTML file path.

    Returns:
        Path to the generated HTML file.
    """
    center_lat = (config.south_lat + config.north_lat) / 2
    center_lon = (config.west_lon + config.east_lon) / 2

    m = folium.Map(
        location=[center_lat, center_lon],
        zoom_start=20,
        tiles=None,
    )

    # Add a simple white background tile
    folium.TileLayer(
        tiles="",
        attr="Indoor Map",
        name="Blank",
    ).add_to(m)

    add_blueprint_overlay(m, config)
    folium.LayerControl().add_to(m)

    if output_path is None:
        output_path = "fhb_indoor_map.html"

    m.save(output_path)
    return output_path
