"""PyQt6 application setup and entry point for honeysnatch GUI."""

from __future__ import annotations

import sys

from honeysnatch import __app_name__, __version__
from honeysnatch.utils.config import load_config
from honeysnatch.utils.logger import setup_logging


def main() -> None:
    """Launch the honeysnatch desktop GUI."""
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt

    # Initialize config and logging
    config = load_config()
    setup_logging(level=config.log_level)

    app = QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("honeysnatch")

    # Apply dark theme stylesheet
    app.setStyleSheet(_DARK_STYLESHEET)

    from honeysnatch.gui.main_window import MainWindow
    window = MainWindow(config=config)
    window.show()

    sys.exit(app.exec())


_DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: 'Segoe UI', 'Ubuntu', sans-serif;
}
QTabWidget::pane {
    border: 1px solid #333;
    background-color: #16213e;
}
QTabBar::tab {
    background-color: #16213e;
    color: #aaa;
    padding: 8px 16px;
    border: 1px solid #333;
    border-bottom: none;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #0f3460;
    color: #e94560;
    font-weight: bold;
}
QTableView, QTreeView, QListView {
    background-color: #16213e;
    color: #e0e0e0;
    gridline-color: #333;
    selection-background-color: #0f3460;
    border: 1px solid #333;
}
QHeaderView::section {
    background-color: #0f3460;
    color: #e94560;
    padding: 6px;
    border: 1px solid #333;
    font-weight: bold;
}
QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: 1px solid #e94560;
    padding: 6px 16px;
    border-radius: 4px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #e94560;
    color: white;
}
QPushButton:pressed {
    background-color: #c73350;
}
QPushButton:disabled {
    background-color: #333;
    color: #666;
    border-color: #555;
}
QComboBox {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #333;
    padding: 4px 8px;
    border-radius: 4px;
}
QComboBox::drop-down {
    border: none;
}
QLineEdit {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #333;
    padding: 4px 8px;
    border-radius: 4px;
}
QStatusBar {
    background-color: #0f3460;
    color: #e0e0e0;
}
QLabel {
    color: #e0e0e0;
}
QGroupBox {
    border: 1px solid #333;
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 12px;
    font-weight: bold;
    color: #e94560;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QProgressBar {
    background-color: #16213e;
    border: 1px solid #333;
    border-radius: 4px;
    text-align: center;
    color: #e0e0e0;
}
QProgressBar::chunk {
    background-color: #e94560;
    border-radius: 3px;
}
QMenuBar {
    background-color: #0f3460;
    color: #e0e0e0;
}
QMenuBar::item:selected {
    background-color: #e94560;
}
QMenu {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #333;
}
QMenu::item:selected {
    background-color: #0f3460;
}
"""


if __name__ == "__main__":
    main()
