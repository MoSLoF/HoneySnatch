"""Data models for CellGuard cellular detection.

Defines cell tower and cellular device representations for
GSM/2G, LTE/4G, and 5G NR networks.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from honeysnatch.core.models import GeoPosition
from honeysnatch.utils.logger import get_logger

log = get_logger("cellular.models")

# MCC/MNC operator lookup cache
_OPERATOR_DB: dict[str, str] = {}


@dataclass
class CellTower:
    """A detected cellular base station (BTS/eNodeB/gNodeB)."""

    cell_id: str
    technology: str  # "GSM", "LTE", "5G_NR"
    mcc: str = ""
    mnc: str = ""
    lac: int = 0  # Location Area Code (GSM/3G)
    tac: int = 0  # Tracking Area Code (LTE/5G)
    arfcn: int = 0  # Absolute Radio Frequency Channel Number (GSM)
    earfcn: int = 0  # E-UTRA ARFCN (LTE)
    frequency_mhz: float = 0.0
    rssi: int = -120
    band: str = ""
    operator: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    position: Optional[GeoPosition] = None
    pci: int = 0  # Physical Cell ID (LTE/5G)
    power: float = 0.0
    metadata: dict = field(default_factory=dict)

    def update(self, rssi: int, position: Optional[GeoPosition] = None) -> None:
        """Update tower with new observation."""
        self.rssi = rssi
        self.last_seen = datetime.now()
        if position:
            self.position = position

    @property
    def plmn(self) -> str:
        """Public Land Mobile Network identifier (MCC-MNC)."""
        return f"{self.mcc}-{self.mnc}" if self.mcc and self.mnc else ""

    @property
    def unique_id(self) -> str:
        """Unique identifier combining technology, PLMN, and cell ID."""
        return f"{self.technology}:{self.plmn}:{self.cell_id}"


@dataclass
class CellularDevice:
    """A detected cellular client device (from passive observation)."""

    identifier: str  # TMSI, IMSI fragment, or other identifier
    device_type: str = "unknown"  # "phone", "modem", "iot", "unknown"
    technology: str = ""
    rssi: int = -120
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    associated_cell: str = ""
    metadata: dict = field(default_factory=dict)

    def update(self, rssi: int) -> None:
        """Update device with new observation."""
        self.rssi = rssi
        self.last_seen = datetime.now()


# --- GSM Band / ARFCN utilities ---

GSM_BANDS = {
    "GSM850": {"arfcn_range": (128, 251), "freq_start": 869.2, "freq_step": 0.2},
    "GSM900": {"arfcn_range": (0, 124), "freq_start": 935.0, "freq_step": 0.2},
    "GSM1800": {"arfcn_range": (512, 885), "freq_start": 1805.2, "freq_step": 0.2},
    "GSM1900": {"arfcn_range": (512, 810), "freq_start": 1930.2, "freq_step": 0.2},
}

# LTE band -> EARFCN range and downlink frequency formula
LTE_BANDS = {
    1: {"earfcn_range": (0, 599), "dl_low": 2110.0, "offset": 0},
    2: {"earfcn_range": (600, 1199), "dl_low": 1930.0, "offset": 600},
    3: {"earfcn_range": (1200, 1949), "dl_low": 1805.0, "offset": 1200},
    4: {"earfcn_range": (1950, 2399), "dl_low": 2110.0, "offset": 1950},
    5: {"earfcn_range": (2400, 2649), "dl_low": 869.0, "offset": 2400},
    7: {"earfcn_range": (2750, 3449), "dl_low": 2620.0, "offset": 2750},
    8: {"earfcn_range": (3450, 3799), "dl_low": 925.0, "offset": 3450},
    12: {"earfcn_range": (5010, 5179), "dl_low": 729.0, "offset": 5010},
    13: {"earfcn_range": (5180, 5279), "dl_low": 746.0, "offset": 5180},
    20: {"earfcn_range": (6150, 6449), "dl_low": 791.0, "offset": 6150},
    25: {"earfcn_range": (8040, 8689), "dl_low": 1930.0, "offset": 8040},
    26: {"earfcn_range": (8690, 9039), "dl_low": 859.0, "offset": 8690},
    28: {"earfcn_range": (9210, 9659), "dl_low": 758.0, "offset": 9210},
    66: {"earfcn_range": (66436, 67335), "dl_low": 2110.0, "offset": 66436},
    71: {"earfcn_range": (68586, 68935), "dl_low": 617.0, "offset": 68586},
}


def arfcn_to_freq(arfcn: int, band: str = "") -> float:
    """Convert GSM ARFCN to downlink frequency in MHz."""
    for band_name, info in GSM_BANDS.items():
        lo, hi = info["arfcn_range"]
        if lo <= arfcn <= hi:
            return info["freq_start"] + (arfcn - lo) * info["freq_step"]
    return 0.0


def earfcn_to_freq(earfcn: int) -> float:
    """Convert LTE EARFCN to downlink frequency in MHz."""
    for band_num, info in LTE_BANDS.items():
        lo, hi = info["earfcn_range"]
        if lo <= earfcn <= hi:
            return info["dl_low"] + (earfcn - info["offset"]) * 0.1
    return 0.0


def earfcn_to_band(earfcn: int) -> int:
    """Determine LTE band number from EARFCN."""
    for band_num, info in LTE_BANDS.items():
        lo, hi = info["earfcn_range"]
        if lo <= earfcn <= hi:
            return band_num
    return 0


# --- MCC/MNC Operator lookup ---

def load_mccmnc_db(path: Optional[str] = None) -> None:
    """Load MCC/MNC operator database from CSV."""
    global _OPERATOR_DB

    if path is None:
        path = str(Path(__file__).parent.parent.parent / "data" / "mccmnc.csv")

    db_path = Path(path)
    if not db_path.exists():
        log.warning("MCC/MNC database not found: %s", path)
        return

    with open(db_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 3:
                mcc, mnc, operator = row[0].strip(), row[1].strip(), row[2].strip()
                _OPERATOR_DB[f"{mcc}-{mnc}"] = operator

    log.info("Loaded %d MCC/MNC entries", len(_OPERATOR_DB))


def lookup_operator(mcc: str, mnc: str) -> str:
    """Look up operator name from MCC/MNC codes."""
    if not _OPERATOR_DB:
        load_mccmnc_db()
    return _OPERATOR_DB.get(f"{mcc}-{mnc}", "")
