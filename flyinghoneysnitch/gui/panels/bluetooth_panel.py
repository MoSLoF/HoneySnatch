"""BlueScout Bluetooth scanning panel for the GUI."""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import Qt, pyqtSignal

from flyinghoneysnitch.utils.config import AppConfig
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("gui.bluetooth")


class BluetoothPanel(QWidget):
    """Bluetooth scanning panel (BlueScout)."""

    device_signal = pyqtSignal(object)  # BluetoothDevice

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self._scanner = None
        self._devices: dict[str, object] = {}
        self._setup_ui()

        self.device_signal.connect(self._on_device_found)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Controls
        controls = QHBoxLayout()
        self.start_btn = QPushButton("Start BT Scan")
        self.start_btn.clicked.connect(self._start_scan)
        controls.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setEnabled(False)
        controls.addWidget(self.stop_btn)

        controls.addStretch()
        self.status_label = QLabel("Status: Idle")
        controls.addWidget(self.status_label)
        self.device_count_label = QLabel("Devices: 0")
        controls.addWidget(self.device_count_label)
        layout.addLayout(controls)

        # Device table
        group = QGroupBox("Bluetooth Devices")
        group_layout = QVBoxLayout(group)
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(5)
        self.device_table.setHorizontalHeaderLabels([
            "Address", "Type", "RSSI", "First Seen", "Last Seen",
        ])
        self.device_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        group_layout.addWidget(self.device_table)
        layout.addWidget(group)

    def _start_scan(self) -> None:
        from flyinghoneysnitch.bluetooth.scanner import BluetoothScanner

        device_path = getattr(self.config, "bluetooth", None)
        device = getattr(device_path, "device", "/dev/ubertooth0") if device_path else "/dev/ubertooth0"

        self._scanner = BluetoothScanner(
            device=device,
            on_device_found=lambda dev: self.device_signal.emit(dev),
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

    def _on_device_found(self, device) -> None:
        """Handle new Bluetooth device on GUI thread."""
        addr = device.address
        self._devices[addr] = device

        # Find existing row or create new one
        for row in range(self.device_table.rowCount()):
            item = self.device_table.item(row, 0)
            if item and item.text() == addr:
                self._set_device_row(row, device)
                self.device_count_label.setText(f"Devices: {len(self._devices)}")
                return

        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        self._set_device_row(row, device)
        self.device_count_label.setText(f"Devices: {len(self._devices)}")

    def _set_device_row(self, row: int, device) -> None:
        """Set device data in a table row."""
        self.device_table.setItem(row, 0, QTableWidgetItem(device.address))
        self.device_table.setItem(row, 1, QTableWidgetItem(device.device_type))

        rssi_item = QTableWidgetItem()
        rssi_item.setData(Qt.ItemDataRole.DisplayRole, device.rssi)
        self.device_table.setItem(row, 2, rssi_item)

        self.device_table.setItem(row, 3, QTableWidgetItem(
            device.first_seen.strftime("%H:%M:%S") if device.first_seen else ""
        ))
        self.device_table.setItem(row, 4, QTableWidgetItem(
            device.last_seen.strftime("%H:%M:%S") if device.last_seen else ""
        ))
