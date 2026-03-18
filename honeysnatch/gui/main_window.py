"""Main window for the honeysnatch desktop GUI."""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QFileDialog,
    QMainWindow,
    QMenuBar,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from honeysnatch import __app_name__, __version__
from honeysnatch.utils.config import AppConfig
from honeysnatch.utils.logger import get_logger

log = get_logger("gui.main")


class MainWindow(QMainWindow):
    """Main application window with tabbed panels."""

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config

        self.setWindowTitle(f"{__app_name__} v{__version__}")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)

        self._setup_menu()
        self._setup_tabs()
        self._setup_status_bar()
        self._setup_refresh_timer()

    def _setup_menu(self) -> None:
        """Set up the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        open_action = QAction("&Open Session...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._open_session)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        export_menu = file_menu.addMenu("&Export")
        export_csv = QAction("Export CSV...", self)
        export_csv.triggered.connect(lambda: self._export("csv"))
        export_menu.addAction(export_csv)
        export_json = QAction("Export JSON...", self)
        export_json.triggered.connect(lambda: self._export("json"))
        export_menu.addAction(export_json)
        export_kml = QAction("Export KML...", self)
        export_kml.triggered.connect(lambda: self._export("kml"))
        export_menu.addAction(export_kml)
        export_report = QAction("Generate Report...", self)
        export_report.triggered.connect(self._generate_report)
        export_menu.addAction(export_report)

        file_menu.addSeparator()

        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # Scan menu
        scan_menu = menubar.addMenu("&Scan")

        start_scan = QAction("&Start Scan", self)
        start_scan.setShortcut(QKeySequence("Ctrl+S"))
        start_scan.triggered.connect(self._start_scan)
        scan_menu.addAction(start_scan)

        stop_scan = QAction("S&top Scan", self)
        stop_scan.setShortcut(QKeySequence("Ctrl+T"))
        stop_scan.triggered.connect(self._stop_scan)
        scan_menu.addAction(stop_scan)

        # View menu
        view_menu = menubar.addMenu("&View")

        # Help menu
        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_tabs(self) -> None:
        """Set up the main tab widget with all panels."""
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Import panels
        from honeysnatch.gui.panels.scan_panel import ScanPanel
        from honeysnatch.gui.panels.map_panel import MapPanel
        from honeysnatch.gui.panels.analysis_panel import AnalysisPanel
        from honeysnatch.gui.panels.monitoring_panel import MonitoringPanel
        from honeysnatch.gui.panels.bluetooth_panel import BluetoothPanel
        from honeysnatch.gui.panels.cellular_panel import CellularPanel
        from honeysnatch.gui.panels.isolation_panel import IsolationPanel

        self.scan_panel = ScanPanel(config=self.config)
        self.map_panel = MapPanel(config=self.config)
        self.analysis_panel = AnalysisPanel(config=self.config)
        self.monitoring_panel = MonitoringPanel(config=self.config)
        self.bluetooth_panel = BluetoothPanel(config=self.config)
        self.cellular_panel = CellularPanel(config=self.config)
        self.isolation_panel = IsolationPanel(config=self.config)

        self.tabs.addTab(self.scan_panel, "Scan")
        self.tabs.addTab(self.map_panel, "Map")
        self.tabs.addTab(self.analysis_panel, "Analysis")
        self.tabs.addTab(self.monitoring_panel, "Monitor")
        self.tabs.addTab(self.bluetooth_panel, "Bluetooth")
        self.tabs.addTab(self.cellular_panel, "Cellular")
        self.tabs.addTab(self.isolation_panel, "Isolation")

    def _setup_status_bar(self) -> None:
        """Set up the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _setup_refresh_timer(self) -> None:
        """Set up a timer for periodic UI updates."""
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_ui)
        self.refresh_timer.start(self.config.gui.refresh_interval_ms)

    def _refresh_ui(self) -> None:
        """Periodic UI refresh."""
        # Update scan panel if scanning
        if hasattr(self.scan_panel, "refresh"):
            self.scan_panel.refresh()

    def _open_session(self) -> None:
        """Open a scan session database file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Session", "",
            "honeysnatch Sessions (*.db);;All Files (*)",
        )
        if path:
            self.analysis_panel.load_session(path)
            self.tabs.setCurrentWidget(self.analysis_panel)

    def _export(self, format: str) -> None:
        """Export current data in the requested format."""
        # Get session from analysis panel or scan panel
        session = None
        if self.analysis_panel._sessions:
            session_ids = list(self.analysis_panel._sessions.keys())
            session = self.analysis_panel._sessions[session_ids[-1]]
        elif self.scan_panel._scanner:
            session = self.scan_panel._scanner.session

        if not session:
            self.status_bar.showMessage("No session data to export")
            return

        filters = {
            "csv": "CSV Files (*.csv)",
            "json": "JSON Files (*.json)",
            "kml": "KML Files (*.kml)",
        }
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Data",
            f"fhs_export_{session.session_id}.{format}",
            filters.get(format, "All Files (*)"),
        )
        if not path:
            return

        try:
            if format == "csv":
                self._export_csv(session, path)
            elif format == "json":
                self._export_json(session, path)
            elif format == "kml":
                from honeysnatch.mapping.export import export_kml
                export_kml(session, output_path=path)
            self.status_bar.showMessage(f"Exported to {path}")
        except Exception as e:
            log.error("Export failed: %s", e)
            self.status_bar.showMessage(f"Export failed: {e}")

    def _export_csv(self, session, path: str) -> None:
        """Export session to CSV."""
        import csv
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "BSSID", "SSID", "Channel", "RSSI", "Encryption",
                "Vendor", "Clients", "Beacons", "First Seen", "Last Seen",
            ])
            for ap in session.access_points.values():
                writer.writerow([
                    ap.bssid, ap.ssid, ap.channel, ap.rssi,
                    ap.encryption.value, ap.vendor, len(ap.clients),
                    ap.beacon_count, ap.first_seen.isoformat(),
                    ap.last_seen.isoformat(),
                ])

    def _export_json(self, session, path: str) -> None:
        """Export session to JSON."""
        import json
        data = {
            "session": {
                "id": session.session_id,
                "name": session.name,
                "interface": session.interface,
                "start_time": session.start_time.isoformat(),
                "end_time": session.end_time.isoformat() if session.end_time else None,
            },
            "access_points": [
                {
                    "bssid": ap.bssid, "ssid": ap.ssid, "channel": ap.channel,
                    "rssi": ap.rssi, "encryption": ap.encryption.value,
                    "vendor": ap.vendor, "clients": len(ap.clients),
                }
                for ap in session.access_points.values()
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def _generate_report(self) -> None:
        """Generate an HTML report."""
        if not self.analysis_panel._sessions:
            self.status_bar.showMessage("No session loaded for report generation")
            return
        self.analysis_panel._generate_report()

    def _start_scan(self) -> None:
        """Start scanning from menu."""
        self.tabs.setCurrentWidget(self.scan_panel)
        self.scan_panel.start_scan()

    def _stop_scan(self) -> None:
        """Stop scanning from menu."""
        self.scan_panel.stop_scan()

    def _show_about(self) -> None:
        """Show about dialog."""
        from PyQt6.QtWidgets import QMessageBox

        QMessageBox.about(
            self,
            f"About {__app_name__}",
            f"<h2>{__app_name__} v{__version__}</h2>"
            "<p>Wireless Discovery & Assessment Tool Suite</p>"
            "<p>Components:</p>"
            "<ul>"
            "<li><b>HoneyBadger Core</b> - Passive WiFi Discovery</li>"
            "<li><b>WarrenMap</b> - RF Visualization & Mapping</li>"
            "<li><b>HoneyView</b> - Post-hoc Analysis</li>"
            "<li><b>SentryWeb</b> - Continuous Monitoring</li>"
            "<li><b>BadgerTrack</b> - Indoor Positioning</li>"
            "<li><b>BlueScout</b> - Bluetooth Scanning</li>"
            "<li><b>CellGuard</b> - Cellular Detection</li>"
            "<li><b>AirSnitch</b> - Client Isolation Testing</li>"
            "</ul>",
        )
