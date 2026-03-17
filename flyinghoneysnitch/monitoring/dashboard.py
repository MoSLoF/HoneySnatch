"""Monitoring dashboard backend for SentryWeb.

Aggregates data from sensors and scanning for the monitoring dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from flyinghoneysnitch.monitoring.alerting import AlertEngine
from flyinghoneysnitch.monitoring.policy import PolicyEngine
from flyinghoneysnitch.monitoring.sensor_manager import SensorManager
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("dashboard")


@dataclass
class DashboardState:
    """Current state of the monitoring dashboard."""

    is_monitoring: bool = False
    total_aps: int = 0
    total_clients: int = 0
    authorized_aps: int = 0
    rogue_aps: int = 0
    open_networks: int = 0
    active_alerts: int = 0
    total_alerts: int = 0
    sensors_online: int = 0
    sensors_offline: int = 0
    policy_violations: int = 0
    uptime_seconds: float = 0
    last_updated: datetime = field(default_factory=datetime.now)


class MonitoringDashboard:
    """Backend for the SentryWeb monitoring dashboard.

    Aggregates data from the alert engine, policy engine, and sensor
    manager to provide a unified monitoring view.
    """

    def __init__(
        self,
        alert_engine: Optional[AlertEngine] = None,
        policy_engine: Optional[PolicyEngine] = None,
        sensor_manager: Optional[SensorManager] = None,
    ) -> None:
        self.alert_engine = alert_engine or AlertEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.sensor_manager = sensor_manager or SensorManager()
        self._start_time: Optional[datetime] = None
        self._state = DashboardState()

    def start(self) -> None:
        """Start monitoring."""
        self._start_time = datetime.now()
        self._state.is_monitoring = True
        log.info("Monitoring dashboard started")

    def stop(self) -> None:
        """Stop monitoring."""
        self._state.is_monitoring = False
        log.info("Monitoring dashboard stopped")

    def get_state(self) -> DashboardState:
        """Get the current dashboard state."""
        self._update_state()
        return self._state

    def _update_state(self) -> None:
        """Refresh the dashboard state from all data sources."""
        self._state.active_alerts = len([
            a for a in self.alert_engine.get_alerts()
            if a.get("severity") in ("critical", "warning")
        ])
        self._state.total_alerts = self.alert_engine.alert_count
        self._state.policy_violations = len(self.policy_engine.get_violations())
        self._state.sensors_online = len(self.sensor_manager.get_online_sensors())
        self._state.sensors_offline = len(self.sensor_manager.get_offline_sensors())

        if self._start_time:
            self._state.uptime_seconds = (datetime.now() - self._start_time).total_seconds()

        self._state.last_updated = datetime.now()
