"""CellGuard cellular scanning panel for the GUI."""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import Qt, pyqtSignal

from honeysnatch.utils.config import AppConfig
from honeysnatch.utils.logger import get_logger

log = get_logger("gui.cellular")


class CellularPanel(QWidget):
    """Cellular scanning and rogue detection panel (CellGuard)."""

    tower_signal = pyqtSignal(object)  # CellTower
    alert_signal = pyqtSignal(object)  # RogueAlert

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self._scanner = None
        self._detector = None
        self._towers: dict[str, object] = {}
        self._setup_ui()

        self.tower_signal.connect(self._on_tower_found)
        self.alert_signal.connect(self._on_alert)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Controls
        controls = QHBoxLayout()

        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self._start_scan)
        controls.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setEnabled(False)
        controls.addWidget(self.stop_btn)

        controls.addSpacing(20)

        self.baseline_load_btn = QPushButton("Load Baseline")
        self.baseline_load_btn.clicked.connect(self._load_baseline)
        controls.addWidget(self.baseline_load_btn)

        self.baseline_save_btn = QPushButton("Save Baseline")
        self.baseline_save_btn.clicked.connect(self._save_baseline)
        controls.addWidget(self.baseline_save_btn)

        controls.addStretch()

        self.status_label = QLabel("Status: Idle")
        controls.addWidget(self.status_label)
        self.tower_count_label = QLabel("Towers: 0")
        controls.addWidget(self.tower_count_label)
        self.alert_count_label = QLabel("Alerts: 0")
        controls.addWidget(self.alert_count_label)

        layout.addLayout(controls)

        # Tower table
        tower_group = QGroupBox("Cell Towers")
        tower_layout = QVBoxLayout(tower_group)
        self.tower_table = QTableWidget()
        self.tower_table.setColumnCount(8)
        self.tower_table.setHorizontalHeaderLabels([
            "Cell ID", "Tech", "PLMN", "Operator",
            "Freq (MHz)", "Band", "RSSI (dBm)", "Status",
        ])
        self.tower_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        tower_layout.addWidget(self.tower_table)
        layout.addWidget(tower_group)

        # Alerts
        alert_group = QGroupBox("Rogue Detection Alerts")
        alert_layout = QVBoxLayout(alert_group)
        self.alert_log = QTextEdit()
        self.alert_log.setReadOnly(True)
        self.alert_log.setMaximumHeight(200)
        alert_layout.addWidget(self.alert_log)
        layout.addWidget(alert_group)

    def _start_scan(self) -> None:
        from honeysnatch.cellular.scanner import CellularScanner
        from honeysnatch.cellular.detector import RogueBaseStationDetector

        cell_cfg = getattr(self.config, "cellular", None)

        rtl = getattr(cell_cfg, "rtlsdr_device", 0) if cell_cfg else 0
        hackrf = getattr(cell_cfg, "hackrf_device", "") if cell_cfg else ""
        do_gsm = getattr(cell_cfg, "scan_gsm", True) if cell_cfg else True
        do_lte = getattr(cell_cfg, "scan_lte", True) if cell_cfg else True

        self._detector = RogueBaseStationDetector()

        self._scanner = CellularScanner(
            rtlsdr_device=rtl,
            hackrf_device=hackrf,
            scan_gsm=do_gsm,
            scan_lte=do_lte,
            on_tower_found=self._handle_tower,
        )
        self._scanner.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Scanning...")

    def _stop_scan(self) -> None:
        if self._scanner:
            self._scanner.stop()
            self._scanner = None

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Stopped")

    def _handle_tower(self, tower) -> None:
        """Called from scanner thread — emit signal for GUI thread."""
        self.tower_signal.emit(tower)

        if self._detector:
            alerts = self._detector.check_tower(tower)
            for alert in alerts:
                self.alert_signal.emit(alert)

    def _on_tower_found(self, tower) -> None:
        """Handle tower on GUI thread."""
        uid = tower.unique_id
        self._towers[uid] = tower

        # Find existing row or create new
        for row in range(self.tower_table.rowCount()):
            item = self.tower_table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == uid:
                self._set_tower_row(row, tower)
                self.tower_count_label.setText(f"Towers: {len(self._towers)}")
                return

        row = self.tower_table.rowCount()
        self.tower_table.insertRow(row)
        self._set_tower_row(row, tower)
        self.tower_count_label.setText(f"Towers: {len(self._towers)}")

    def _set_tower_row(self, row: int, tower) -> None:
        """Set tower data in a table row."""
        cid_item = QTableWidgetItem(tower.cell_id)
        cid_item.setData(Qt.ItemDataRole.UserRole, tower.unique_id)
        self.tower_table.setItem(row, 0, cid_item)
        self.tower_table.setItem(row, 1, QTableWidgetItem(tower.technology))
        self.tower_table.setItem(row, 2, QTableWidgetItem(tower.plmn or "-"))
        self.tower_table.setItem(row, 3, QTableWidgetItem(tower.operator or "Unknown"))
        self.tower_table.setItem(row, 4, QTableWidgetItem(f"{tower.frequency_mhz:.1f}"))
        self.tower_table.setItem(row, 5, QTableWidgetItem(tower.band or "-"))

        rssi_item = QTableWidgetItem()
        rssi_item.setData(Qt.ItemDataRole.DisplayRole, tower.rssi)
        self.tower_table.setItem(row, 6, rssi_item)

        self.tower_table.setItem(row, 7, QTableWidgetItem("OK"))

    def _on_alert(self, alert) -> None:
        """Handle rogue detection alert on GUI thread."""
        color_map = {"critical": "#ff4444", "warning": "#ffaa00", "info": "#aaaaaa"}
        color = color_map.get(alert.severity, "#ffffff")
        self.alert_log.append(
            f'<span style="color:{color}">'
            f"[{alert.severity.upper()}] {alert.alert_type}: {alert.message}"
            f"</span>"
        )
        alert_count = self._detector.alert_count if self._detector else 0
        self.alert_count_label.setText(f"Alerts: {alert_count}")

        # Mark tower row as suspicious
        uid = alert.tower.unique_id
        for row in range(self.tower_table.rowCount()):
            item = self.tower_table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == uid:
                status = "ALERT" if alert.severity == "critical" else "WARN"
                self.tower_table.setItem(row, 7, QTableWidgetItem(status))
                break

    def _load_baseline(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Baseline", "",
            "JSON Files (*.json);;All Files (*)",
        )
        if path and self._detector:
            self._detector.load_baseline_file(path)
            self.status_label.setText(f"Baseline loaded from {path}")

    def _save_baseline(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Baseline", "cellguard_baseline.json",
            "JSON Files (*.json);;All Files (*)",
        )
        if path:
            from honeysnatch.cellular.detector import RogueBaseStationDetector
            detector = self._detector or RogueBaseStationDetector()
            towers = list(self._towers.values())
            detector.save_baseline(towers, path)
            self.status_label.setText(f"Baseline saved: {len(towers)} towers")
