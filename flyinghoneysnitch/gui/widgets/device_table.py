"""Sortable, filterable device table widget for the scan panel."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, QSortFilterProxyModel, QAbstractTableModel, QModelIndex
from PyQt6.QtWidgets import QLineEdit, QTableView, QVBoxLayout, QWidget

from flyinghoneysnitch.core.models import AccessPoint
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("gui.device_table")


class AccessPointTableModel(QAbstractTableModel):
    """Table model for access point data."""

    HEADERS = [
        "BSSID", "SSID", "Channel", "RSSI", "Max RSSI",
        "Encryption", "Vendor", "Clients", "Beacons", "Band",
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._data: list[AccessPoint] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._data)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None

        ap = self._data[index.row()]
        col = index.column()

        match col:
            case 0: return ap.bssid
            case 1: return ap.ssid or "[Hidden]"
            case 2: return ap.channel
            case 3: return ap.rssi
            case 4: return ap.max_rssi
            case 5: return ap.encryption.value
            case 6: return ap.vendor
            case 7: return len(ap.clients)
            case 8: return ap.beacon_count
            case 9: return ap.band.value

        return None

    def update_data(self, aps: list[AccessPoint]) -> None:
        """Replace all data."""
        self.beginResetModel()
        self._data = list(aps)
        self.endResetModel()

    def add_or_update(self, ap: AccessPoint) -> None:
        """Add or update a single AP."""
        for i, existing in enumerate(self._data):
            if existing.bssid == ap.bssid:
                self._data[i] = ap
                self.dataChanged.emit(
                    self.index(i, 0),
                    self.index(i, self.columnCount() - 1),
                )
                return

        self.beginInsertRows(QModelIndex(), len(self._data), len(self._data))
        self._data.append(ap)
        self.endInsertRows()


class FilterableDeviceTable(QWidget):
    """A device table with a search/filter bar."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Filter input
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter devices...")
        self.filter_input.textChanged.connect(self._on_filter_changed)
        layout.addWidget(self.filter_input)

        # Table with proxy model for filtering/sorting
        self.model = AccessPointTableModel()
        self.proxy = QSortFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)  # Filter all columns

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

    def _on_filter_changed(self, text: str) -> None:
        self.proxy.setFilterFixedString(text)
