"""CellGuard — cellular network detection and rogue base station monitoring.

Supports GSM, LTE, and 5G NR scanning via SDR (RTL-SDR / HackRF)
and passive ModemManager (mmcli) fallback.
"""

from honeysnatch.cellular.models import (
    CellTower,
    CellularDevice,
    arfcn_to_freq,
    earfcn_to_freq,
    earfcn_to_band,
    lookup_operator,
    load_mccmnc_db,
)
from honeysnatch.cellular.nr_scanner import NrScanner, nrarfcn_to_freq, freq_to_nr_band
from honeysnatch.cellular.gsm_scanner import GsmScanner
from honeysnatch.cellular.lte_scanner import LteScanner
from honeysnatch.cellular.scanner import CellularScanner
from honeysnatch.cellular.detector import RogueBaseStationDetector, RogueAlert
from honeysnatch.cellular.classifier import classify_cell_tower

__all__ = [
    "CellTower",
    "CellularDevice",
    "arfcn_to_freq",
    "earfcn_to_freq",
    "earfcn_to_band",
    "lookup_operator",
    "load_mccmnc_db",
    "NrScanner",
    "nrarfcn_to_freq",
    "freq_to_nr_band",
    "GsmScanner",
    "LteScanner",
    "CellularScanner",
    "RogueBaseStationDetector",
    "RogueAlert",
    "classify_cell_tower",
]
