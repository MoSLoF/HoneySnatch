"""SentryWeb monitoring panel for the GUI."""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal

from honeysnatch.utils.config import AppConfig
from honeysnatch.utils.logger import get_logger

log = get_logger("gui.monitor")


class MonitoringPanel(QWidget):
    """Continuous monitoring panel (SentryWeb)."""

    alert_signal = pyqtSignal(list)  # list of alert dicts

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self._scanner = None
        self._alert_engine = None
        self._dashboard = None
        self._refresh_timer = None
        self._authorized_bssids: set[str] = set()
        self._authorized_ssids: set[str] = set()
        self._setup_ui()

        self.alert_signal.connect(self._on_alerts)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Controls
        controls = QHBoxLayout()
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self._start_monitoring)
        controls.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self._stop_monitoring)
        self.stop_btn.setEnabled(False)
        controls.addWidget(self.stop_btn)

        self.load_known_btn = QPushButton("Load Known APs...")
        self.load_known_btn.clicked.connect(self._load_known_aps)
        controls.addWidget(self.load_known_btn)

        controls.addStretch()
        self.status_label = QLabel("Status: Idle")
        controls.addWidget(self.status_label)
        layout.addLayout(controls)

        # Content
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Alert table
        alert_group = QGroupBox("Security Alerts")
        alert_layout = QVBoxLayout(alert_group)
        self.alert_table = QTableWidget()
        self.alert_table.setColumnCount(5)
        self.alert_table.setHorizontalHeaderLabels([
            "Time", "Severity", "Type", "Message", "Device",
        ])
        alert_layout.addWidget(self.alert_table)
        splitter.addWidget(alert_group)

        # Event log
        log_group = QGroupBox("Event Log")
        log_layout = QVBoxLayout(log_group)
        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        log_layout.addWidget(self.event_log)
        splitter.addWidget(log_group)

        splitter.setSizes([400, 200])
        layout.addWidget(splitter)

    def _start_monitoring(self) -> None:
        from honeysnatch.core.scanner import WifiScanner
        from honeysnatch.monitoring.alerting import AlertEngine
        from honeysnatch.monitoring.dashboard import MonitoringDashboard

        self._alert_engine = AlertEngine(
            authorized_bssids=self._authorized_bssids or None,
            authorized_ssids=self._authorized_ssids or None,
            alert_on_rogue=True,
            alert_on_new_client=True,
            alert_on_open=True,
        )
        self._dashboard = MonitoringDashboard(alert_engine=self._alert_engine)

        interface = self.config.scan.interface
        self._scanner = WifiScanner(
            interface=interface,
            scan_5ghz=self.config.scan.scan_5ghz,
            hop_interval=self.config.scan.hop_interval,
        )

        def _on_event(event):
            alerts = self._alert_engine.process_event(event)
            if alerts:
                self.alert_signal.emit(alerts)

        self._scanner.on_event(_on_event)
        self._scanner.start()
        self._dashboard.start()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_dashboard)
        self._refresh_timer.start(2000)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Monitoring...")
        self.event_log.append(f"Monitoring started on {interface}")
        if self._authorized_bssids:
            self.event_log.append(
                f"Loaded {len(self._authorized_bssids)} authorized BSSIDs, "
                f"{len(self._authorized_ssids)} authorized SSIDs"
            )

    def _stop_monitoring(self) -> None:
        if self._refresh_timer:
            self._refresh_timer.stop()
            self._refresh_timer = None

        if self._scanner:
            self._scanner.stop()
            self._scanner = None

        if self._dashboard:
            self._dashboard.stop()
            self._dashboard = None

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Stopped")
        self.event_log.append("Monitoring stopped")

    def _on_alerts(self, alerts: list[dict]) -> None:
        """Handle new alerts on the GUI thread."""
        for alert in alerts:
            row = self.alert_table.rowCount()
            self.alert_table.insertRow(row)
            self.alert_table.setItem(row, 0, QTableWidgetItem(
                alert.get("timestamp", "")[:19]
            ))
            self.alert_table.setItem(row, 1, QTableWidgetItem(
                alert.get("severity", "")
            ))
            self.alert_table.setItem(row, 2, QTableWidgetItem(
                alert.get("type", "")
            ))
            self.alert_table.setItem(row, 3, QTableWidgetItem(
                alert.get("message", "")
            ))
            self.alert_table.setItem(row, 4, QTableWidgetItem(
                alert.get("bssid", alert.get("mac", ""))
            ))
            self.event_log.append(
                f"[{alert.get('severity', '').upper()}] {alert.get('message', '')}"
            )

    def _refresh_dashboard(self) -> None:
        """Periodic dashboard state refresh."""
        if self._dashboard:
            state = self._dashboard.get_state()
            self.status_label.setText(
                f"Status: Monitoring | Alerts: {state.total_alerts} | "
                f"Uptime: {int(state.uptime_seconds)}s"
            )

    def _load_known_aps(self) -> None:
        """Load authorized BSSIDs/SSIDs from a text file.

        File format: one entry per line.
        Lines starting with 'BSSID:' or containing a MAC address pattern are BSSIDs.
        Lines starting with 'SSID:' are SSIDs.
        Plain lines are treated as SSIDs.
        """
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Known APs",
            "", "Text Files (*.txt);;All Files (*)",
        )
        if not path:
            return

        import re
        mac_pattern = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")

        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.upper().startswith("BSSID:"):
                    self._authorized_bssids.add(line[6:].strip().lower())
                elif line.upper().startswith("SSID:"):
                    self._authorized_ssids.add(line[5:].strip())
                elif mac_pattern.match(line):
                    self._authorized_bssids.add(line.lower())
                else:
                    self._authorized_ssids.add(line)

        self.event_log.append(
            f"Loaded known APs: {len(self._authorized_bssids)} BSSIDs, "
            f"{len(self._authorized_ssids)} SSIDs"
        )
