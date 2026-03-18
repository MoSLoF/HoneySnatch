"""IMU (Inertial Measurement Unit) sensor integration for BadgerTrack.

Reads accelerometer, gyroscope, magnetometer, and barometric data
from USB-connected IMU sensors for indoor positioning.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from honeysnatch.utils.logger import get_logger

log = get_logger("imu")


@dataclass
class ImuReading:
    """A single reading from the IMU sensor."""

    # Accelerometer (m/s^2)
    accel_x: float = 0.0
    accel_y: float = 0.0
    accel_z: float = 0.0

    # Gyroscope (deg/s)
    gyro_x: float = 0.0
    gyro_y: float = 0.0
    gyro_z: float = 0.0

    # Magnetometer (uT)
    mag_x: float = 0.0
    mag_y: float = 0.0
    mag_z: float = 0.0

    # Barometric pressure (hPa)
    pressure: float = 0.0
    temperature: float = 0.0

    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def heading(self) -> float:
        """Calculate magnetic heading from magnetometer data (degrees 0-360)."""
        import math
        heading = math.degrees(math.atan2(self.mag_y, self.mag_x))
        return (heading + 360) % 360

    @property
    def altitude_estimate(self) -> float:
        """Estimate altitude from barometric pressure (meters above sea level).

        Uses the barometric formula with standard atmosphere.
        """
        if self.pressure <= 0:
            return 0.0
        return 44330.0 * (1.0 - (self.pressure / 1013.25) ** 0.1903)


class ImuSensor:
    """Reads data from a USB-connected IMU sensor.

    Supports generic serial IMU devices (like the Caribou sensor)
    that output structured data over USB serial.
    """

    def __init__(
        self,
        port: str = "/dev/ttyUSB0",
        baud_rate: int = 115200,
        on_reading: Optional[Callable[[ImuReading], None]] = None,
    ) -> None:
        self.port = port
        self.baud_rate = baud_rate
        self.on_reading = on_reading

        self._serial = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._latest_reading: Optional[ImuReading] = None
        self._lock = threading.Lock()

    @property
    def latest_reading(self) -> Optional[ImuReading]:
        with self._lock:
            return self._latest_reading

    @property
    def is_connected(self) -> bool:
        return self._serial is not None and self._running

    def start(self) -> bool:
        """Connect to the IMU sensor and start reading."""
        try:
            import serial
            self._serial = serial.Serial(
                port=self.port,
                baudrate=self.baud_rate,
                timeout=1,
            )
            self._running = True
            self._thread = threading.Thread(
                target=self._read_loop,
                name="ImuSensor",
                daemon=True,
            )
            self._thread.start()
            log.info("IMU sensor connected on %s", self.port)
            return True

        except ImportError:
            log.error("pyserial not installed. Install with: pip install pyserial")
            return False
        except Exception as e:
            log.error("Failed to connect to IMU on %s: %s", self.port, e)
            return False

    def stop(self) -> None:
        """Disconnect from the IMU sensor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        if self._serial:
            self._serial.close()
            self._serial = None
        log.info("IMU sensor disconnected")

    def _read_loop(self) -> None:
        """Background loop that reads IMU data packets."""
        while self._running and self._serial:
            try:
                line = self._serial.readline().decode("ascii", errors="replace").strip()
                if not line:
                    continue

                reading = self._parse_reading(line)
                if reading:
                    with self._lock:
                        self._latest_reading = reading
                    if self.on_reading:
                        try:
                            self.on_reading(reading)
                        except Exception as e:
                            log.error("IMU callback error: %s", e)

            except Exception as e:
                log.debug("IMU read error: %s", e)
                time.sleep(0.01)

    def _parse_reading(self, line: str) -> Optional[ImuReading]:
        """Parse a CSV line from the IMU sensor.

        Expected format: ax,ay,az,gx,gy,gz,mx,my,mz,pressure,temp
        """
        try:
            parts = line.split(",")
            if len(parts) >= 9:
                return ImuReading(
                    accel_x=float(parts[0]),
                    accel_y=float(parts[1]),
                    accel_z=float(parts[2]),
                    gyro_x=float(parts[3]),
                    gyro_y=float(parts[4]),
                    gyro_z=float(parts[5]),
                    mag_x=float(parts[6]),
                    mag_y=float(parts[7]),
                    mag_z=float(parts[8]),
                    pressure=float(parts[9]) if len(parts) > 9 else 0.0,
                    temperature=float(parts[10]) if len(parts) > 10 else 0.0,
                )
        except (ValueError, IndexError):
            pass
        return None
