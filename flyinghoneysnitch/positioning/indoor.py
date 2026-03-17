"""Indoor dead-reckoning positioning for BadgerTrack.

Provides position tracking in GPS-denied indoor environments
using IMU sensor data with step detection and heading estimation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from flyinghoneysnitch.core.models import GeoPosition
from flyinghoneysnitch.positioning.imu import ImuReading
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("indoor")


@dataclass
class IndoorPosition:
    """Position in a local coordinate system (meters from origin)."""

    x: float = 0.0  # East-West (meters)
    y: float = 0.0  # North-South (meters)
    floor: int = 0
    heading: float = 0.0  # degrees
    timestamp: datetime = field(default_factory=datetime.now)

    def to_geo(self, origin: GeoPosition) -> GeoPosition:
        """Convert indoor position to geographic coordinates.

        Args:
            origin: The GPS position of the building entrance / starting point.
        """
        d_lat = self.y / 111320.0
        d_lon = self.x / (111320.0 * math.cos(math.radians(origin.latitude)))

        return GeoPosition(
            latitude=origin.latitude + d_lat,
            longitude=origin.longitude + d_lon,
            altitude=origin.altitude + (self.floor * 3.0) if origin.altitude else None,
            source="indoor",
            timestamp=self.timestamp,
        )


class IndoorTracker:
    """Tracks position indoors using IMU dead-reckoning.

    Uses a pedometer (step detection) combined with a compass
    heading to estimate movement through a building.
    """

    def __init__(
        self,
        step_length: float = 0.75,
        step_threshold: float = 1.8,
        origin: Optional[GeoPosition] = None,
    ) -> None:
        """
        Args:
            step_length: Average step length in meters.
            step_threshold: Acceleration threshold for step detection (m/s^2 deviation from gravity).
            origin: GPS position of the starting point (for geo-referencing).
        """
        self.step_length = step_length
        self.step_threshold = step_threshold
        self.origin = origin

        self._position = IndoorPosition()
        self._step_count = 0
        self._last_accel_mag = 9.81
        self._step_phase = False  # True when in a step
        self._heading_filter: list[float] = []
        self._ref_pressure: Optional[float] = None

    @property
    def position(self) -> IndoorPosition:
        return self._position

    @property
    def step_count(self) -> int:
        return self._step_count

    def set_origin(self, origin: GeoPosition, x: float = 0, y: float = 0) -> None:
        """Set the geographic origin and initial indoor position."""
        self.origin = origin
        self._position = IndoorPosition(x=x, y=y)

    def update(self, reading: ImuReading) -> IndoorPosition:
        """Process an IMU reading and update position.

        Args:
            reading: The IMU sensor reading.

        Returns:
            Updated indoor position.
        """
        # Update heading (low-pass filtered)
        heading = reading.heading
        self._heading_filter.append(heading)
        if len(self._heading_filter) > 5:
            self._heading_filter.pop(0)
        self._position.heading = self._average_heading(self._heading_filter)

        # Step detection
        accel_mag = math.sqrt(
            reading.accel_x ** 2 + reading.accel_y ** 2 + reading.accel_z ** 2
        )

        deviation = abs(accel_mag - 9.81)

        if deviation > self.step_threshold and not self._step_phase:
            # Step detected (rising edge)
            self._step_phase = True
            self._step_count += 1

            # Update position based on heading
            heading_rad = math.radians(self._position.heading)
            self._position.x += self.step_length * math.sin(heading_rad)
            self._position.y += self.step_length * math.cos(heading_rad)
            self._position.timestamp = datetime.now()

        elif deviation < self.step_threshold * 0.5:
            self._step_phase = False

        self._last_accel_mag = accel_mag

        # Floor detection from barometric pressure changes
        if reading.pressure > 0:
            self._update_floor(reading)

        return self._position

    def get_geo_position(self) -> Optional[GeoPosition]:
        """Convert current indoor position to geographic coordinates."""
        if self.origin:
            return self._position.to_geo(self.origin)
        return None

    def reset(self, x: float = 0, y: float = 0) -> None:
        """Reset position to a known point."""
        self._position = IndoorPosition(x=x, y=y)
        self._step_count = 0
        self._step_phase = False
        self._heading_filter.clear()
        self._ref_pressure = None

    def _update_floor(self, reading: ImuReading) -> None:
        """Estimate floor changes from barometric pressure.

        Uses the barometric formula: ~12 Pa per meter of altitude change.
        Assumes ~3m per floor. The first reading establishes the reference
        pressure (floor 0).
        """
        if self._ref_pressure is None:
            self._ref_pressure = reading.pressure
            return

        # Pressure decreases with altitude: higher altitude = lower pressure
        delta_h = (self._ref_pressure - reading.pressure) / 12.0
        new_floor = round(delta_h / 3.0)

        if new_floor != self._position.floor:
            log.info("Floor change detected: %d -> %d (pressure: %.1f Pa)",
                     self._position.floor, new_floor, reading.pressure)
            self._position.floor = new_floor

    @staticmethod
    def _average_heading(headings: list[float]) -> float:
        """Calculate average heading accounting for circular wraparound."""
        if not headings:
            return 0.0

        sin_sum = sum(math.sin(math.radians(h)) for h in headings)
        cos_sum = sum(math.cos(math.radians(h)) for h in headings)

        avg = math.degrees(math.atan2(sin_sum, cos_sum))
        return (avg + 360) % 360
