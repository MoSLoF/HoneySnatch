"""Sensor fusion for combining GPS and IMU position data.

Fuses GPS outdoor positions with IMU inertial measurements to provide
continuous position tracking, especially during GPS outages.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Optional

from flyinghoneysnitch.core.models import GeoPosition
from flyinghoneysnitch.positioning.imu import ImuReading
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("fusion")


class PositionFusion:
    """Fuses GPS and IMU data for continuous position tracking.

    Uses a simple complementary filter approach:
    - When GPS is available: Use GPS position with IMU for smoothing
    - When GPS is unavailable: Use IMU dead-reckoning from last known position
    """

    def __init__(
        self,
        gps_weight: float = 0.9,
        imu_weight: float = 0.1,
        gps_timeout_s: float = 10.0,
    ) -> None:
        """
        Args:
            gps_weight: Weight for GPS position (0-1).
            imu_weight: Weight for IMU-derived position (0-1).
            gps_timeout_s: Seconds before GPS fix is considered stale.
        """
        self.gps_weight = gps_weight
        self.imu_weight = imu_weight
        self.gps_timeout_s = gps_timeout_s

        self._last_gps: Optional[GeoPosition] = None
        self._last_gps_time: Optional[datetime] = None
        self._last_imu: Optional[ImuReading] = None
        self._current_position: Optional[GeoPosition] = None

        # Dead-reckoning state
        self._heading: float = 0.0  # degrees
        self._velocity: float = 0.0  # m/s estimated
        self._step_length: float = 0.75  # meters per step (configurable)
        self._last_update: Optional[datetime] = None

    @property
    def position(self) -> Optional[GeoPosition]:
        """The current fused position."""
        return self._current_position

    @property
    def gps_available(self) -> bool:
        """Whether GPS fix is currently available (not stale)."""
        if not self._last_gps_time:
            return False
        age = (datetime.now() - self._last_gps_time).total_seconds()
        return age < self.gps_timeout_s

    def update_gps(self, position: GeoPosition) -> GeoPosition:
        """Update with a new GPS fix.

        Args:
            position: The GPS position.

        Returns:
            The fused position.
        """
        self._last_gps = position
        self._last_gps_time = datetime.now()

        if self._current_position and self._last_imu:
            # Fuse GPS with IMU-derived position
            fused = GeoPosition(
                latitude=(
                    position.latitude * self.gps_weight
                    + self._current_position.latitude * self.imu_weight
                ),
                longitude=(
                    position.longitude * self.gps_weight
                    + self._current_position.longitude * self.imu_weight
                ),
                altitude=position.altitude,
                accuracy=position.accuracy,
                source="fused_gps",
            )
            self._current_position = fused
        else:
            self._current_position = position

        self._last_update = datetime.now()
        return self._current_position

    def update_imu(self, reading: ImuReading) -> Optional[GeoPosition]:
        """Update with a new IMU reading.

        If GPS is stale, uses dead-reckoning to estimate position.

        Args:
            reading: The IMU sensor reading.

        Returns:
            Updated position, or None if no position is available.
        """
        self._last_imu = reading
        self._heading = reading.heading

        if not self._current_position:
            return None

        if not self.gps_available and self._last_update:
            # Dead-reckoning: use IMU to estimate movement
            dt = (datetime.now() - self._last_update).total_seconds()
            if dt > 0 and dt < 5:  # Ignore large gaps
                position = self._dead_reckon(reading, dt)
                if position:
                    self._current_position = position
                    self._last_update = datetime.now()

        return self._current_position

    def _dead_reckon(self, reading: ImuReading, dt: float) -> Optional[GeoPosition]:
        """Estimate position change from IMU data using dead reckoning.

        Uses accelerometer magnitude to detect steps and magnetometer
        for heading.
        """
        if not self._current_position:
            return None

        # Detect movement from accelerometer magnitude
        accel_mag = math.sqrt(
            reading.accel_x ** 2 + reading.accel_y ** 2 + reading.accel_z ** 2
        )

        # Simple step detection: acceleration above threshold indicates movement
        is_moving = abs(accel_mag - 9.81) > 1.5  # Deviation from gravity

        if not is_moving:
            return self._current_position

        # Estimate distance traveled
        distance = self._step_length * dt  # Rough estimate

        # Calculate new position
        heading_rad = math.radians(self._heading)
        lat = self._current_position.latitude
        lon = self._current_position.longitude

        # Convert distance to degree offsets
        d_lat = (distance * math.cos(heading_rad)) / 111320.0
        d_lon = (distance * math.sin(heading_rad)) / (111320.0 * math.cos(math.radians(lat)))

        return GeoPosition(
            latitude=lat + d_lat,
            longitude=lon + d_lon,
            altitude=reading.altitude_estimate if reading.pressure > 0 else self._current_position.altitude,
            source="dead_reckoning",
            timestamp=datetime.now(),
        )

    def reset(self) -> None:
        """Reset all position tracking state."""
        self._last_gps = None
        self._last_gps_time = None
        self._last_imu = None
        self._current_position = None
        self._last_update = None
