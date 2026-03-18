"""RF signal strength heatmap generation.

Creates interpolated RF coverage maps from collected signal strength
measurements at known geographic positions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np

from honeysnatch.core.models import GeoPosition
from honeysnatch.utils.logger import get_logger

log = get_logger("rf_map")


@dataclass
class SignalMeasurement:
    """A signal strength measurement at a specific location."""

    bssid: str
    rssi: int  # dBm
    position: GeoPosition


@dataclass
class RFHeatmapData:
    """Generated heatmap data ready for visualization."""

    latitudes: np.ndarray  # 1D array of latitude grid points
    longitudes: np.ndarray  # 1D array of longitude grid points
    values: np.ndarray  # 2D array of interpolated signal strengths
    bssid: Optional[str]  # The AP this heatmap is for (None = composite)
    min_rssi: float
    max_rssi: float


class RFMapper:
    """Generates RF signal strength heatmaps from measurements.

    Collects signal measurements and produces interpolated heatmaps
    showing estimated signal coverage across a geographic area.
    """

    def __init__(self) -> None:
        self._measurements: list[SignalMeasurement] = []

    def add_measurement(self, bssid: str, rssi: int, position: GeoPosition) -> None:
        """Add a signal strength measurement."""
        self._measurements.append(SignalMeasurement(
            bssid=bssid, rssi=rssi, position=position,
        ))

    def add_measurements(self, measurements: list[SignalMeasurement]) -> None:
        """Add multiple measurements at once."""
        self._measurements.extend(measurements)

    @property
    def measurement_count(self) -> int:
        return len(self._measurements)

    def generate_heatmap(
        self,
        bssid: Optional[str] = None,
        grid_size: int = 100,
        method: str = "rbf",
    ) -> Optional[RFHeatmapData]:
        """Generate an interpolated RF heatmap.

        Args:
            bssid: Filter for a specific AP. None = composite of all APs.
            grid_size: Number of grid points in each dimension.
            method: Interpolation method ('rbf', 'idw', 'linear').

        Returns:
            RFHeatmapData with interpolated values, or None if insufficient data.
        """
        # Filter measurements
        if bssid:
            measurements = [m for m in self._measurements if m.bssid == bssid]
        else:
            measurements = self._measurements

        if len(measurements) < 3:
            log.warning("Need at least 3 measurements for interpolation (got %d)", len(measurements))
            return None

        # Extract coordinates and values
        lats = np.array([m.position.latitude for m in measurements])
        lons = np.array([m.position.longitude for m in measurements])
        rssi_values = np.array([m.rssi for m in measurements], dtype=float)

        # Create grid
        lat_grid = np.linspace(lats.min(), lats.max(), grid_size)
        lon_grid = np.linspace(lons.min(), lons.max(), grid_size)
        lon_mesh, lat_mesh = np.meshgrid(lon_grid, lat_grid)

        # Interpolate
        if method == "rbf":
            grid_values = self._interpolate_rbf(lats, lons, rssi_values, lat_mesh, lon_mesh)
        elif method == "idw":
            grid_values = self._interpolate_idw(lats, lons, rssi_values, lat_mesh, lon_mesh)
        else:
            grid_values = self._interpolate_linear(lats, lons, rssi_values, lat_mesh, lon_mesh)

        return RFHeatmapData(
            latitudes=lat_grid,
            longitudes=lon_grid,
            values=grid_values,
            bssid=bssid,
            min_rssi=float(rssi_values.min()),
            max_rssi=float(rssi_values.max()),
        )

    def _interpolate_rbf(
        self,
        lats: np.ndarray,
        lons: np.ndarray,
        values: np.ndarray,
        lat_mesh: np.ndarray,
        lon_mesh: np.ndarray,
    ) -> np.ndarray:
        """Radial Basis Function interpolation (best quality)."""
        try:
            from scipy.interpolate import RBFInterpolator

            points = np.column_stack([lats, lons])
            grid_points = np.column_stack([lat_mesh.ravel(), lon_mesh.ravel()])

            rbf = RBFInterpolator(points, values, kernel="thin_plate_spline", smoothing=1.0)
            grid_values = rbf(grid_points).reshape(lat_mesh.shape)

            # Clamp to reasonable dBm range
            grid_values = np.clip(grid_values, -100, 0)
            return grid_values

        except ImportError:
            log.warning("scipy not available, falling back to IDW")
            return self._interpolate_idw(lats, lons, values, lat_mesh, lon_mesh)

    def _interpolate_idw(
        self,
        lats: np.ndarray,
        lons: np.ndarray,
        values: np.ndarray,
        lat_mesh: np.ndarray,
        lon_mesh: np.ndarray,
        power: float = 2.0,
    ) -> np.ndarray:
        """Inverse Distance Weighting interpolation."""
        grid_values = np.zeros_like(lat_mesh)

        for i in range(lat_mesh.shape[0]):
            for j in range(lat_mesh.shape[1]):
                distances = np.sqrt(
                    (lats - lat_mesh[i, j]) ** 2 + (lons - lon_mesh[i, j]) ** 2
                )
                # Avoid division by zero
                distances = np.maximum(distances, 1e-10)
                weights = 1.0 / distances ** power
                grid_values[i, j] = np.sum(weights * values) / np.sum(weights)

        return np.clip(grid_values, -100, 0)

    def _interpolate_linear(
        self,
        lats: np.ndarray,
        lons: np.ndarray,
        values: np.ndarray,
        lat_mesh: np.ndarray,
        lon_mesh: np.ndarray,
    ) -> np.ndarray:
        """Linear interpolation using scipy griddata."""
        try:
            from scipy.interpolate import griddata

            points = np.column_stack([lats, lons])
            grid_values = griddata(
                points, values, (lat_mesh, lon_mesh),
                method="linear", fill_value=-100,
            )
            return np.clip(grid_values, -100, 0)

        except ImportError:
            return self._interpolate_idw(lats, lons, values, lat_mesh, lon_mesh)

    def get_measurements_for(self, bssid: str) -> list[SignalMeasurement]:
        """Get all measurements for a specific AP."""
        return [m for m in self._measurements if m.bssid == bssid]

    def clear(self) -> None:
        """Clear all measurements."""
        self._measurements.clear()
