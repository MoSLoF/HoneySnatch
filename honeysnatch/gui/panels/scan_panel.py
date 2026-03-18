"""Scan panel for live wireless scanning in the GUI."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from honeysnatch.core.models import ScanEvent
from honeysnatch.utils.config import AppConfig
from honeysnatch.utils.logger import get_logger

log = get_logger("gui.scan")


class ScanPanel(QWidget):
    """Live scanning panel with device table and controls."""

    scan_event = pyqtSignal(object)  # ScanEvent

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self._scanner = None
        self._setup_ui()

        # Connect signal for thread-safe UI updates
        self.scan_event.connect(self._handle_scan_event)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # --- Controls ---
        controls = QGroupBox("Scan Controls")
        controls_layout = QHBoxLayout(controls)

        controls_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(150)
        controls_layout.addWidget(self.interface_combo)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh_interfaces)
        controls_layout.addWidget(self.refresh_btn)

        controls_layout.addStretch()

        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        controls_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn)

        layout.addWidget(controls)

        # --- Status ---
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Idle")
        status_layout.addWidget(self.status_label)
        self.ap_count_label = QLabel("APs: 0")
        status_layout.addWidget(self.ap_count_label)
        self.client_count_label = QLabel("Clients: 0")
        status_layout.addWidget(self.client_count_label)
        self.channel_label = QLabel("Channel: -")
        status_layout.addWidget(self.channel_label)
        self.packet_label = QLabel("Packets: 0")
        status_layout.addWidget(self.packet_label)
        status_layout.addStretch()
        layout.addLayout(status_layout)

        # --- Device Tables ---
        splitter = QSplitter(Qt.Orientation.Vertical)

        # AP Table
        ap_group = QGroupBox("Access Points")
        ap_layout = QVBoxLayout(ap_group)
        self.ap_table = QTableWidget()
        self.ap_table.setColumnCount(9)
        self.ap_table.setHorizontalHeaderLabels([
            "BSSID", "SSID", "Channel", "RSSI", "Max RSSI",
            "Encryption", "Vendor", "Clients", "Beacons",
        ])
        self.ap_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.ap_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.ap_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ap_table.setSortingEnabled(True)
        ap_layout.addWidget(self.ap_table)
        splitter.addWidget(ap_group)

        # Client Table
        cl_group = QGroupBox("Clients")
        cl_layout = QVBoxLayout(cl_group)
        self.client_table = QTableWidget()
        self.client_table.setColumnCount(6)
        self.client_table.setHorizontalHeaderLabels([
            "MAC", "Associated AP", "RSSI", "Vendor", "Probes", "Data Pkts",
        ])
        self.client_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.client_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.client_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.client_table.setSortingEnabled(True)
        cl_layout.addWidget(self.client_table)
        splitter.addWidget(cl_group)

        splitter.setSizes([500, 300])
        layout.addWidget(splitter)

    def start_scan(self) -> None:
        """Start a new scan."""
        interface = self.interface_combo.currentText()
        if not interface:
            self.status_label.setText("Status: No interface selected")
            return

        from honeysnatch.core.scanner import WifiScanner

        self._scanner = WifiScanner(
            interface=interface,
            scan_5ghz=self.config.scan.scan_5ghz,
            hop_interval=self.config.scan.hop_interval,
        )

        # Connect events (thread-safe via signal)
        self._scanner.on_event(lambda e: self.scan_event.emit(e))

        self._scanner.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Scanning...")

    def stop_scan(self) -> None:
        """Stop the current scan."""
        if self._scanner:
            self._scanner.stop()
            self._scanner = None

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Stopped")

    def refresh(self) -> None:
        """Periodic refresh of statistics."""
        if self._scanner and self._scanner.is_running:
            self.ap_count_label.setText(f"APs: {self._scanner.ap_count}")
            self.client_count_label.setText(f"Clients: {self._scanner.client_count}")
            self.channel_label.setText(f"Channel: {self._scanner.current_channel}")
            self.packet_label.setText(f"Packets: {self._scanner.packet_count}")

    def _handle_scan_event(self, event: ScanEvent) -> None:
        """Handle scan events on the GUI thread."""
        if event.event_type in ("ap_found", "ap_updated") and event.ap:
            self._update_ap_table(event.ap)
        elif event.event_type in ("client_found", "client_updated") and event.client:
            self._update_client_table(event.client)

    def _update_ap_table(self, ap) -> None:
        """Add or update an AP row in the table."""
        # Find existing row
        for row in range(self.ap_table.rowCount()):
            item = self.ap_table.item(row, 0)
            if item and item.text() == ap.bssid:
                self._set_ap_row(row, ap)
                return

        # New row
        row = self.ap_table.rowCount()
        self.ap_table.insertRow(row)
        self._set_ap_row(row, ap)

    def _set_ap_row(self, row: int, ap) -> None:
        """Set AP data in a table row."""
        self.ap_table.setSortingEnabled(False)
        self.ap_table.setItem(row, 0, QTableWidgetItem(ap.bssid))
        self.ap_table.setItem(row, 1, QTableWidgetItem(ap.ssid or "[Hidden]"))
        self.ap_table.setItem(row, 2, QTableWidgetItem(str(ap.channel)))

        rssi_item = QTableWidgetItem()
        rssi_item.setData(Qt.ItemDataRole.DisplayRole, ap.rssi)
        self.ap_table.setItem(row, 3, rssi_item)

        max_rssi_item = QTableWidgetItem()
        max_rssi_item.setData(Qt.ItemDataRole.DisplayRole, ap.max_rssi)
        self.ap_table.setItem(row, 4, max_rssi_item)

        self.ap_table.setItem(row, 5, QTableWidgetItem(ap.encryption.value))
        self.ap_table.setItem(row, 6, QTableWidgetItem(ap.vendor))

        clients_item = QTableWidgetItem()
        clients_item.setData(Qt.ItemDataRole.DisplayRole, len(ap.clients))
        self.ap_table.setItem(row, 7, clients_item)

        beacons_item = QTableWidgetItem()
        beacons_item.setData(Qt.ItemDataRole.DisplayRole, ap.beacon_count)
        self.ap_table.setItem(row, 8, beacons_item)
        self.ap_table.setSortingEnabled(True)

    def _update_client_table(self, client) -> None:
        """Add or update a client row in the table."""
        for row in range(self.client_table.rowCount()):
            item = self.client_table.item(row, 0)
            if item and item.text() == client.mac:
                self._set_client_row(row, client)
                return

        row = self.client_table.rowCount()
        self.client_table.insertRow(row)
        self._set_client_row(row, client)

    def _set_client_row(self, row: int, client) -> None:
        """Set client data in a table row."""
        self.client_table.setSortingEnabled(False)
        self.client_table.setItem(row, 0, QTableWidgetItem(client.mac))
        self.client_table.setItem(row, 1, QTableWidgetItem(client.bssid or "-"))

        rssi_item = QTableWidgetItem()
        rssi_item.setData(Qt.ItemDataRole.DisplayRole, client.rssi)
        self.client_table.setItem(row, 2, rssi_item)

        self.client_table.setItem(row, 3, QTableWidgetItem(client.vendor))
        self.client_table.setItem(row, 4, QTableWidgetItem(", ".join(client.probe_requests[:5])))

        data_item = QTableWidgetItem()
        data_item.setData(Qt.ItemDataRole.DisplayRole, client.data_count)
        self.client_table.setItem(row, 5, data_item)
        self.client_table.setSortingEnabled(True)

    def _refresh_interfaces(self) -> None:
        """Refresh the wireless interface list."""
        self.interface_combo.clear()
        try:
            from honeysnatch.utils.interfaces import list_wireless_interfaces
            interfaces = list_wireless_interfaces()
            for iface in interfaces:
                suffix = " [monitor]" if iface.mode == "monitor" else ""
                self.interface_combo.addItem(f"{iface.name}{suffix}")
        except Exception as e:
            log.error("Failed to list interfaces: %s", e)
