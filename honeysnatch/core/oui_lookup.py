"""OUI (Organizationally Unique Identifier) lookup for MAC address vendor resolution.

Maps the first 3 octets of a MAC address to the manufacturer/vendor name
using the IEEE OUI database.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Optional

from honeysnatch.utils.logger import get_logger

log = get_logger("oui")

# In-memory OUI cache: prefix -> vendor name
_oui_db: dict[str, str] = {}
_loaded = False


def load_oui_database(oui_path: Optional[str] = None) -> int:
    """Load the OUI database from a CSV file.

    Expected CSV format: MA-L prefix (e.g., "AA:BB:CC"), vendor name
    Falls back to a bundled database if no path is specified.

    Args:
        oui_path: Path to an OUI CSV file.

    Returns:
        Number of OUI entries loaded.
    """
    global _oui_db, _loaded

    if oui_path is None:
        oui_path = str(Path(__file__).parent.parent.parent / "data" / "oui.csv")

    path = Path(oui_path)
    if not path.exists():
        log.warning("OUI database not found at %s", oui_path)
        _loaded = True
        return 0

    _oui_db.clear()

    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    prefix = _normalize_prefix(row[0])
                    if prefix:
                        _oui_db[prefix] = row[1].strip()
    except Exception as e:
        log.error("Failed to load OUI database: %s", e)

    _loaded = True
    log.info("Loaded %d OUI entries", len(_oui_db))
    return len(_oui_db)


def lookup_vendor(mac: str) -> str:
    """Look up the vendor/manufacturer for a MAC address.

    Args:
        mac: MAC address in any common format (AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, etc.)

    Returns:
        Vendor name or empty string if not found.
    """
    if not _loaded:
        load_oui_database()

    prefix = _normalize_prefix(mac)
    if not prefix:
        return ""

    return _oui_db.get(prefix, "")


def _normalize_prefix(mac: str) -> str:
    """Extract and normalize the OUI prefix (first 3 octets) from a MAC address.

    Returns uppercase colon-separated prefix like "AA:BB:CC", or empty string if invalid.
    """
    # Strip all separators
    clean = re.sub(r"[:\-.\s]", "", mac.strip().upper())

    if len(clean) < 6:
        return ""

    # Take first 6 hex chars (3 octets)
    prefix = clean[:6]
    if not all(c in "0123456789ABCDEF" for c in prefix):
        return ""

    return f"{prefix[0:2]}:{prefix[2:4]}:{prefix[4:6]}"


# Common vendors for quick reference (fallback when no OUI DB is loaded)
COMMON_VENDORS = {
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "AC:DE:48": "Amazon",
    "F0:27:2D": "Amazon",
    "A4:77:33": "Google",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:0A:95": "Apple",
    "28:6A:BA": "Apple",
    "3C:22:FB": "Apple",
    "70:56:81": "Apple",
    "AC:BC:32": "Apple",
    "F4:5C:89": "Apple",
    "00:26:AB": "Samsung",
    "5C:3A:45": "Samsung",
    "00:23:68": "Intel",
    "68:05:CA": "Intel",
    "00:24:D7": "Intel",
}
