"""Custom status bar widget showing GPS, scan, and device status."""

from __future__ import annotations

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget

from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("gui.status_bar")


class ScanStatusBar(QWidget):
    """Status bar showing real-time scan metrics.

    Displays: GPS status, scan status, channel, AP count, client count, packets.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(28)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 0, 4, 0)
        layout.setSpacing(16)

        self.gps_label = self._make_label("GPS: No Fix")
        self.scan_label = self._make_label("Scan: Idle")
        self.channel_label = self._make_label("Ch: -")
        self.ap_label = self._make_label("APs: 0")
        self.client_label = self._make_label("Clients: 0")
        self.packet_label = self._make_label("Pkts: 0")
        self.time_label = self._make_label("00:00:00")

        layout.addWidget(self.gps_label)
        layout.addWidget(self._separator())
        layout.addWidget(self.scan_label)
        layout.addWidget(self._separator())
        layout.addWidget(self.channel_label)
        layout.addWidget(self._separator())
        layout.addWidget(self.ap_label)
        layout.addWidget(self._separator())
        layout.addWidget(self.client_label)
        layout.addWidget(self._separator())
        layout.addWidget(self.packet_label)
        layout.addStretch()
        layout.addWidget(self.time_label)

    def update_gps(self, has_fix: bool, lat: float = 0, lon: float = 0) -> None:
        if has_fix:
            self.gps_label.setText(f"GPS: {lat:.4f}, {lon:.4f}")
            self.gps_label.setStyleSheet("color: #00ff88;")
        else:
            self.gps_label.setText("GPS: No Fix")
            self.gps_label.setStyleSheet("color: #ff4444;")

    def update_scan(self, is_scanning: bool, channel: int = 0) -> None:
        if is_scanning:
            self.scan_label.setText("Scan: Active")
            self.scan_label.setStyleSheet("color: #00ff88;")
            self.channel_label.setText(f"Ch: {channel}")
        else:
            self.scan_label.setText("Scan: Idle")
            self.scan_label.setStyleSheet("color: #aaa;")
            self.channel_label.setText("Ch: -")

    def update_counts(self, aps: int, clients: int, packets: int) -> None:
        self.ap_label.setText(f"APs: {aps}")
        self.client_label.setText(f"Clients: {clients}")
        self.packet_label.setText(f"Pkts: {packets}")

    def update_time(self, elapsed_seconds: float) -> None:
        h = int(elapsed_seconds // 3600)
        m = int((elapsed_seconds % 3600) // 60)
        s = int(elapsed_seconds % 60)
        self.time_label.setText(f"{h:02d}:{m:02d}:{s:02d}")

    def _make_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet("color: #aaa; font-size: 11px; font-family: monospace;")
        return label

    def _separator(self) -> QFrame:
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet("color: #333;")
        return sep
