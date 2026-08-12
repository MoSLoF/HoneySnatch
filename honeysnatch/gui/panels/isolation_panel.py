"""Client Isolation Testing panel for the honeysnatch GUI.

CONSENT (review finding HS-02):
The panel collects a target BSSID and an explicit "I have permission
to attack" checkbox, and constructs the runner with a matching
:class:`Authorization`. Without both, only Simulate mode is enabled.
The runner-level gate is the enforcement point; this UI just makes it
easy for an authorized operator to supply what the gate needs.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
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

log = get_logger("gui.isolation")


class IsolationPanel(QWidget):
    """Client isolation vulnerability testing panel (AirSnitch)."""

    result_signal = pyqtSignal(object)

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self._runner = None
        self._results = []
        self._setup_ui()
        self.result_signal.connect(self._on_result)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Configuration Section
        config_group = QGroupBox("Test Configuration")
        config_layout = QVBoxLayout(config_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Interface:"))
        self.iface_edit = QLineEdit()
        self.iface_edit.setPlaceholderText("e.g. wlan0")
        self.iface_edit.setMaximumWidth(150)
        row1.addWidget(self.iface_edit)
        row1.addWidget(QLabel("2nd Interface:"))
        self.iface2_edit = QLineEdit()
        self.iface2_edit.setPlaceholderText("e.g. wlan1")
        self.iface2_edit.setMaximumWidth(150)
        row1.addWidget(self.iface2_edit)
        row1.addStretch()
        config_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Config File:"))
        self.config_edit = QLineEdit()
        self.config_edit.setPlaceholderText("Path to client.conf")
        row2.addWidget(self.config_edit)
        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self._browse_config)
        row2.addWidget(self.browse_btn)
        row2.addWidget(QLabel("Server:"))
        self.server_edit = QLineEdit("8.8.8.8")
        self.server_edit.setMaximumWidth(150)
        row2.addWidget(self.server_edit)
        config_layout.addLayout(row2)

        # Consent row (HS-02): target BSSID + explicit ack + simulate toggle.
        # Live tests refuse to run unless (BSSID valid AND ack checked) OR
        # simulate is on. The runner re-enforces this — see
        # honeysnatch/isolation/runner.py::_gate_live_run.
        row_consent = QHBoxLayout()
        row_consent.addWidget(QLabel("Target BSSID:"))
        self.target_bssid_edit = QLineEdit()
        self.target_bssid_edit.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.target_bssid_edit.setMaximumWidth(180)
        row_consent.addWidget(self.target_bssid_edit)
        self.ack_checkbox = QCheckBox(
            "I have permission to test this BSSID (logged as consent evidence)"
        )
        row_consent.addWidget(self.ack_checkbox)
        row_consent.addStretch()
        self.simulate_checkbox = QCheckBox("Simulate (no on-air packets)")
        self.simulate_checkbox.setChecked(True)  # safe default in the GUI
        row_consent.addWidget(self.simulate_checkbox)
        config_layout.addLayout(row_consent)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Test:"))
        self.test_combo = QComboBox()
        self.test_combo.addItems([
            "Context Override", "C2C ARP", "C2C Ethernet", "C2C IP",
            "C2C Broadcast", "Port Steal (Downlink)", "Port Steal (Uplink)",
            "GTK Shared Check", "GTK Inject", "C2M", "Run All",
        ])
        row3.addWidget(self.test_combo)
        row3.addStretch()
        self.start_btn = QPushButton("Run Test")
        self.start_btn.clicked.connect(self._start_test)
        row3.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop_test)
        self.stop_btn.setEnabled(False)
        row3.addWidget(self.stop_btn)
        config_layout.addLayout(row3)

        layout.addWidget(config_group)

        # Results Table
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout(results_group)
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Attack", "Outcome", "BSSID", "Details", "Timestamp",
        ])
        self.results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        results_layout.addWidget(self.results_table)
        layout.addWidget(results_group)

        # Log Output
        log_group = QGroupBox("Test Log")
        log_layout = QVBoxLayout(log_group)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(200)
        log_layout.addWidget(self.log_output)
        layout.addWidget(log_group)

    def _browse_config(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Config File", "",
            "Config Files (*.conf);;All Files (*)",
        )
        if path:
            self.config_edit.setText(path)

    def _start_test(self) -> None:
        iface = self.iface_edit.text().strip()
        if not iface:
            self.log_output.append("Error: No interface specified")
            return

        # HS-02: build an Authorization for the runner. Simulate mode
        # doesn't need one; live tests need (valid BSSID + ack).
        simulate = self.simulate_checkbox.isChecked()
        authz = None
        target_bssid = self.target_bssid_edit.text().strip()
        if not simulate:
            from honeysnatch.isolation.consent import (
                Authorization,
                BadBssidError,
                ConsentRequiredError,
                require_consent,
            )
            if not target_bssid:
                self.log_output.append(
                    "Refused: live tests require a Target BSSID. "
                    "Enter one and check 'I have permission…', or enable Simulate."
                )
                return
            if not self.ack_checkbox.isChecked():
                self.log_output.append(
                    f"Refused: live tests require the 'I have permission' checkbox. "
                    f"Target: {target_bssid}"
                )
                return
            try:
                # HS-02R (v0.1.4): require_consent returns the receipt
                # that from_cli_ack must consume — no receipt, no live
                # authorization.
                receipt = require_consent(
                    bssid=target_bssid,
                    ack_bssid=target_bssid,
                    simulate=False,
                    context={"command": "gui:isolation", "interface": iface},
                )
                authz = Authorization.from_cli_ack(target_bssid, receipt)
            except (ConsentRequiredError, BadBssidError) as exc:
                self.log_output.append(f"Refused: {exc}")
                return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        test_name = self.test_combo.currentText()
        self.log_output.append(f"Starting test: {test_name}")

        from honeysnatch.isolation.runner import IsolationTestRunner
        self._runner = IsolationTestRunner(
            interface=iface,
            config_file=self.config_edit.text().strip(),
            simulate=simulate,
            authorization=authz,
        )

        second_iface = self.iface2_edit.text().strip()
        test_idx = self.test_combo.currentIndex()

        try:
            if test_idx == 10:  # Run All
                if not second_iface:
                    self.log_output.append("Error: Run All requires 2nd interface")
                    return
                session = self._runner.run_all(second_iface)
                for result in session.results:
                    self.result_signal.emit(result)
            elif test_idx == 7:  # GTK Shared Check
                result = self._runner.run_gtk_check(second_iface or iface)
                self.result_signal.emit(result)
            elif test_idx in (5, 6):  # Port Steal
                direction = "downlink" if test_idx == 5 else "uplink"
                result = self._runner.run_port_steal(
                    second_iface or iface, direction=direction
                )
                self.result_signal.emit(result)
            elif test_idx == 9:  # C2M
                result = self._runner.run_client2monitor(second_iface or iface)
                self.result_signal.emit(result)
            else:
                modes = ["", "arp", "ethernet", "ip", "broadcast"]
                mode = modes[test_idx] if test_idx < len(modes) else "ip"
                result = self._runner.run_client2client(
                    second_iface or iface, mode=mode
                )
                self.result_signal.emit(result)
        except Exception as e:
            self.log_output.append(f"Error: {e}")
        finally:
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def _stop_test(self) -> None:
        self.log_output.append("Test stopped")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _on_result(self, result) -> None:
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(result.attack_type.value))

        outcome_text = result.outcome.value.upper()
        outcome_item = QTableWidgetItem(outcome_text)
        self.results_table.setItem(row, 1, outcome_item)
        self.results_table.setItem(row, 2, QTableWidgetItem(result.target_bssid))
        self.results_table.setItem(row, 3, QTableWidgetItem(result.details[:80]))
        self.results_table.setItem(
            row, 4, QTableWidgetItem(result.timestamp.strftime("%H:%M:%S"))
        )

        self.log_output.append(
            f"{result.attack_type.value}: {result.outcome.value} - {result.details}"
        )
        self._results.append(result)
