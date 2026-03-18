"""Remote sensor management for SentryWeb.

Manages distributed wireless sensors for continuous monitoring,
handling registration, heartbeat, and data collection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from honeysnatch.utils.logger import get_logger

log = get_logger("sensor_manager")


@dataclass
class SensorInfo:
    """Information about a remote monitoring sensor."""

    sensor_id: str
    name: str
    sensor_type: str  # "unifi", "flyingfox", "ubertooth"
    ip_address: str = ""
    location: str = ""
    status: str = "unknown"  # online, offline, unknown
    last_heartbeat: Optional[datetime] = None
    capabilities: list[str] = field(default_factory=list)  # wifi, cellular, bluetooth
    metadata: dict = field(default_factory=dict)

    @property
    def is_online(self) -> bool:
        if not self.last_heartbeat:
            return False
        return (datetime.now() - self.last_heartbeat) < timedelta(minutes=5)


class SensorManager:
    """Manages a fleet of remote wireless monitoring sensors.

    Supports:
    - Ubiquiti UniFi APs (for WiFi monitoring)
    - Flying Fox sensors (for cellular/WiFi/Bluetooth)
    - Ubertooth sensors (for Bluetooth)
    """

    def __init__(self) -> None:
        self._sensors: dict[str, SensorInfo] = {}

    def register_sensor(
        self,
        sensor_id: str,
        name: str,
        sensor_type: str,
        ip_address: str = "",
        location: str = "",
        capabilities: Optional[list[str]] = None,
    ) -> SensorInfo:
        """Register a new sensor.

        Args:
            sensor_id: Unique sensor identifier.
            name: Human-readable sensor name.
            sensor_type: Type of sensor hardware.
            ip_address: Network address of the sensor.
            location: Physical location description.
            capabilities: List of monitoring capabilities.

        Returns:
            The registered SensorInfo.
        """
        sensor = SensorInfo(
            sensor_id=sensor_id,
            name=name,
            sensor_type=sensor_type,
            ip_address=ip_address,
            location=location,
            capabilities=capabilities or [],
            status="online",
            last_heartbeat=datetime.now(),
        )
        self._sensors[sensor_id] = sensor
        log.info("Registered sensor: %s (%s) at %s", name, sensor_type, location)
        return sensor

    def unregister_sensor(self, sensor_id: str) -> bool:
        """Remove a sensor from management."""
        if sensor_id in self._sensors:
            del self._sensors[sensor_id]
            return True
        return False

    def heartbeat(self, sensor_id: str) -> bool:
        """Process a heartbeat from a sensor."""
        if sensor_id in self._sensors:
            self._sensors[sensor_id].last_heartbeat = datetime.now()
            self._sensors[sensor_id].status = "online"
            return True
        return False

    def get_sensor(self, sensor_id: str) -> Optional[SensorInfo]:
        """Get sensor info by ID."""
        return self._sensors.get(sensor_id)

    def list_sensors(self) -> list[SensorInfo]:
        """List all registered sensors."""
        return list(self._sensors.values())

    def get_online_sensors(self) -> list[SensorInfo]:
        """Get all currently online sensors."""
        self._update_statuses()
        return [s for s in self._sensors.values() if s.is_online]

    def get_offline_sensors(self) -> list[SensorInfo]:
        """Get all currently offline sensors."""
        self._update_statuses()
        return [s for s in self._sensors.values() if not s.is_online]

    def _update_statuses(self) -> None:
        """Update sensor statuses based on heartbeat timeouts."""
        for sensor in self._sensors.values():
            if sensor.is_online:
                sensor.status = "online"
            else:
                sensor.status = "offline"
