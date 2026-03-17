"""HoneyView analysis panel for the GUI."""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import Qt

from flyinghoneysnitch.utils.config import AppConfig
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("gui.analysis")


class AnalysisPanel(QWidget):
    """Post-hoc analysis panel (HoneyView)."""

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self._sessions = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Controls
        controls = QHBoxLayout()
        load_btn = QPushButton("Load Session...")
        load_btn.clicked.connect(self._load_session_dialog)
        controls.addWidget(load_btn)

        load_dir_btn = QPushButton("Load Directory...")
        load_dir_btn.clicked.connect(self._load_directory_dialog)
        controls.addWidget(load_dir_btn)

        compare_btn = QPushButton("Compare Sessions")
        compare_btn.clicked.connect(self._compare_sessions)
        controls.addWidget(compare_btn)

        report_btn = QPushButton("Generate Report")
        report_btn.clicked.connect(self._generate_report)
        controls.addWidget(report_btn)

        controls.addStretch()
        layout.addLayout(controls)

        # Main content
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Session list
        session_group = QGroupBox("Sessions")
        session_layout = QVBoxLayout(session_group)
        self.session_list = QListWidget()
        self.session_list.currentItemChanged.connect(self._on_session_selected)
        session_layout.addWidget(self.session_list)
        splitter.addWidget(session_group)

        # Analysis tabs
        self.analysis_tabs = QTabWidget()

        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.analysis_tabs.addTab(self.summary_text, "Summary")

        # Details tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.analysis_tabs.addTab(self.details_text, "Details")

        # Anomalies tab
        self.anomalies_text = QTextEdit()
        self.anomalies_text.setReadOnly(True)
        self.analysis_tabs.addTab(self.anomalies_text, "Anomalies")

        splitter.addWidget(self.analysis_tabs)
        splitter.setSizes([300, 900])

        layout.addWidget(splitter)

    def load_session(self, db_path: str) -> None:
        """Load a session from a database file."""
        from flyinghoneysnitch.analysis.session_manager import SessionManager

        manager = SessionManager()
        session = manager.load_session(db_path)

        if session:
            self._sessions[session.session_id] = session
            self.session_list.addItem(f"{session.name} ({session.ap_count} APs)")
            self._show_summary(session)

    def _load_session_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Session", "", "Database Files (*.db);;All Files (*)",
        )
        if path:
            self.load_session(path)

    def _load_directory_dialog(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            from flyinghoneysnitch.analysis.session_manager import SessionManager
            manager = SessionManager()
            sessions = manager.load_directory(directory)
            for session in sessions:
                self._sessions[session.session_id] = session
                self.session_list.addItem(f"{session.name} ({session.ap_count} APs)")

    def _on_session_selected(self, current, previous) -> None:
        if current:
            idx = self.session_list.row(current)
            session_ids = list(self._sessions.keys())
            if idx < len(session_ids):
                self._show_summary(self._sessions[session_ids[idx]])

    def _show_summary(self, session) -> None:
        from flyinghoneysnitch.analysis.reports import generate_summary_text
        self.summary_text.setPlainText(generate_summary_text(session))

    def _compare_sessions(self) -> None:
        """Compare two sessions and display the diff."""
        session_ids = list(self._sessions.keys())
        if len(session_ids) < 2:
            self.details_text.setPlainText(
                "Need at least 2 sessions loaded to compare.\n"
                "Load more sessions using the buttons above."
            )
            return

        # Use the selected items if two are selected, otherwise use last two
        selected = self.session_list.selectedItems()
        if len(selected) == 2:
            idx_a = self.session_list.row(selected[0])
            idx_b = self.session_list.row(selected[1])
        else:
            idx_a = len(session_ids) - 2
            idx_b = len(session_ids) - 1

        session_a = self._sessions[session_ids[idx_a]]
        session_b = self._sessions[session_ids[idx_b]]

        from flyinghoneysnitch.analysis.session_manager import SessionManager
        manager = SessionManager()
        diff = manager.compare_sessions(session_a, session_b)

        lines = [
            f"Session Comparison",
            f"  A: {session_a.name} ({session_a.ap_count} APs)",
            f"  B: {session_b.name} ({session_b.ap_count} APs)",
            "",
        ]

        if diff.new_aps:
            lines.append(f"New APs ({len(diff.new_aps)}):")
            for ap in diff.new_aps:
                lines.append(f"  + {ap.bssid}  {ap.ssid or '[Hidden]'}  ch{ap.channel}  {ap.encryption.value}")
            lines.append("")

        if diff.removed_aps:
            lines.append(f"Removed APs ({len(diff.removed_aps)}):")
            for ap in diff.removed_aps:
                lines.append(f"  - {ap.bssid}  {ap.ssid or '[Hidden]'}  ch{ap.channel}")
            lines.append("")

        if diff.encryption_changes:
            lines.append(f"Encryption Changes ({len(diff.encryption_changes)}):")
            for bssid, old_enc, new_enc in diff.encryption_changes:
                lines.append(f"  ! {bssid}: {old_enc} -> {new_enc}")
            lines.append("")

        if diff.ssid_changes:
            lines.append(f"SSID Changes ({len(diff.ssid_changes)}):")
            for bssid, old_ssid, new_ssid in diff.ssid_changes:
                lines.append(f"  ! {bssid}: '{old_ssid}' -> '{new_ssid}'")
            lines.append("")

        if diff.new_clients:
            lines.append(f"New Clients ({len(diff.new_clients)}):")
            for cl in diff.new_clients:
                lines.append(f"  + {cl.mac}  {cl.vendor or ''}")
            lines.append("")

        if diff.removed_clients:
            lines.append(f"Removed Clients ({len(diff.removed_clients)}):")
            for cl in diff.removed_clients:
                lines.append(f"  - {cl.mac}  {cl.vendor or ''}")
            lines.append("")

        if not any([diff.new_aps, diff.removed_aps, diff.encryption_changes,
                    diff.ssid_changes, diff.new_clients, diff.removed_clients]):
            lines.append("No significant differences found.")

        self.details_text.setPlainText("\n".join(lines))
        self.analysis_tabs.setCurrentWidget(self.details_text)

    def _generate_report(self) -> None:
        """Generate an HTML report for the selected session."""
        session_ids = list(self._sessions.keys())
        if not session_ids:
            return

        session = self._sessions[session_ids[-1]]

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", f"fhb_report_{session.session_id}.html",
            "HTML Files (*.html)",
        )
        if path:
            from flyinghoneysnitch.analysis.reports import generate_html_report
            generate_html_report(session, output_path=path)
