"""Map visualization panel for WarrenMap in the GUI."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from honeysnatch.utils.config import AppConfig
from honeysnatch.utils.logger import get_logger

log = get_logger("gui.map")


class MapPanel(QWidget):
    """Map visualization panel using embedded web view for Folium maps."""

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self._session = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Controls
        controls = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh Map")
        self.refresh_btn.clicked.connect(self._refresh_map)
        controls.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("Export KML")
        self.export_btn.clicked.connect(self._export_kml)
        controls.addWidget(self.export_btn)

        controls.addStretch()
        layout.addLayout(controls)

        # Map view (QWebEngineView if available, fallback to label)
        try:
            from PyQt6.QtWebEngineWidgets import QWebEngineView
            self.web_view = QWebEngineView()
            self.web_view.setHtml(
                "<html><body style='background:#1a1a2e;color:#aaa;display:flex;"
                "align-items:center;justify-content:center;height:100vh;'>"
                "<h2>Start a scan to see the map</h2>"
                "</body></html>"
            )
            layout.addWidget(self.web_view)
        except ImportError:
            self.web_view = None
            layout.addWidget(QLabel(
                "Map view requires PyQt6-WebEngine.\n"
                "Install with: pip install PyQt6-WebEngine"
            ))

    def load_map(self, html_path: str) -> None:
        """Load a generated Folium map HTML file."""
        if self.web_view:
            self.web_view.setUrl(QUrl.fromLocalFile(html_path))

    def set_session(self, session) -> None:
        """Set the scan session to visualize."""
        self._session = session
        self._refresh_map()

    def _refresh_map(self) -> None:
        """Regenerate and reload the map from the current session."""
        if not self._session:
            log.info("Map refresh requested but no session data available")
            return

        if not self.web_view:
            return

        import tempfile
        from honeysnatch.mapping.renderer import render_session_map

        try:
            tmp = tempfile.NamedTemporaryFile(
                suffix=".html", delete=False, prefix="fhb_map_",
            )
            tmp.close()
            render_session_map(self._session, output_path=tmp.name)
            self.load_map(tmp.name)
            log.info("Map refreshed")
        except Exception as e:
            log.error("Map refresh failed: %s", e)

    def _export_kml(self) -> None:
        """Export current session to KML."""
        if not self._session:
            return

        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self, "Export KML",
            f"fhb_map_{self._session.session_id}.kml",
            "KML Files (*.kml)",
        )
        if path:
            from honeysnatch.mapping.export import export_kml
            try:
                export_kml(self._session, output_path=path)
            except Exception as e:
                log.error("KML export failed: %s", e)
