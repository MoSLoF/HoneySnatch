"""LTE/4G cell tower scanning using srsRAN cell_search and HackRF.

Wraps the srsRAN cell_search utility to discover nearby LTE eNodeBs
and extract cell parameters (PCI, EARFCN, frequency, signal strength).
"""

from __future__ import annotations

import re
import subprocess
from typing import Optional

from honeysnatch.cellular.models import (
    CellTower,
    earfcn_to_band,
    earfcn_to_freq,
    lookup_operator,
)
from honeysnatch.utils.logger import get_logger

log = get_logger("cellular.lte")

# Standard EARFCN values to scan for common US/EU LTE bands
DEFAULT_LTE_EARFCNS = {
    1: [300],       # Band 1 (2100 MHz)
    2: [900],       # Band 2 (1900 MHz)
    3: [1575],      # Band 3 (1800 MHz)
    4: [2175],      # Band 4 (AWS)
    5: [2525],      # Band 5 (850 MHz)
    7: [3100],      # Band 7 (2600 MHz)
    12: [5095],     # Band 12 (700 MHz)
    13: [5230],     # Band 13 (700 MHz)
    20: [6300],     # Band 20 (800 MHz)
    25: [8365],     # Band 25 (1900 MHz)
    26: [8865],     # Band 26 (850 MHz)
    66: [66886],    # Band 66 (AWS-3)
    71: [68761],    # Band 71 (600 MHz)
}


class LteScanner:
    """LTE cell tower scanner using srsRAN cell_search + HackRF."""

    def __init__(self, device_name: str = "hackrf", device_args: str = "") -> None:
        self.device_name = device_name
        self.device_args = device_args

    def scan(self, bands: Optional[list[int]] = None) -> list[CellTower]:
        """Scan for LTE eNodeBs across specified bands.

        Args:
            bands: LTE band numbers to scan (e.g., [1, 3, 7, 20]).
                   Defaults to common bands if None.

        Returns:
            List of discovered CellTower objects.
        """
        if bands is None:
            bands = [2, 4, 5, 7, 12, 13, 66, 71]  # Common US bands

        towers = []
        for band in bands:
            try:
                band_towers = self.scan_band(band)
                towers.extend(band_towers)
            except Exception as e:
                log.error("LTE scan failed for band %d: %s", band, e)

        return towers

    def scan_band(self, band: int) -> list[CellTower]:
        """Scan a specific LTE band for eNodeBs.

        Args:
            band: LTE band number.

        Returns:
            List of discovered CellTower objects on this band.
        """
        earfcns = DEFAULT_LTE_EARFCNS.get(band)
        if not earfcns:
            log.warning("No default EARFCNs configured for band %d", band)
            return []

        towers = []
        for earfcn in earfcns:
            try:
                result = self._run_cell_search(earfcn)
                towers.extend(result)
            except FileNotFoundError:
                log.error(
                    "cell_search not found. Install srsRAN: "
                    "sudo apt install srsran"
                )
                return []
            except subprocess.TimeoutExpired:
                log.warning("cell_search timed out for EARFCN %d", earfcn)

        return towers

    def _run_cell_search(self, earfcn: int) -> list[CellTower]:
        """Run srsRAN cell_search for a specific EARFCN."""
        cmd = [
            "cell_search",
            f"--rf.device_name={self.device_name}",
        ]
        if self.device_args:
            cmd.append(f"--rf.device_args={self.device_args}")
        cmd.append(f"--earfcn_start={earfcn}")
        cmd.append(f"--earfcn_end={earfcn}")

        log.info("Running: %s", " ".join(cmd))
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )

        return self._parse_cell_search_output(result.stdout + result.stderr)

    def _parse_cell_search_output(self, output: str) -> list[CellTower]:
        """Parse cell_search output into CellTower objects.

        cell_search output varies by version but typically includes:
            Found CELL ...  PCI=XXX, EARFCN=XXXX, Freq XXX.X MHz, RSSI=XX.X dBm
        """
        towers = []

        # Pattern for srsRAN cell_search output
        # Matches lines like: "Found Cell:  PCI=123, PRB=50, Ports=2, EARFCN=1234"
        pci_pattern = re.compile(
            r"(?:Found|CELL)\s*.*?"
            r"PCI[=:\s]*(\d+).*?"
            r"EARFCN[=:\s]*(\d+)",
            re.IGNORECASE,
        )

        # Also try to extract power/RSSI
        power_pattern = re.compile(
            r"(?:RSSI|PSS|power)[=:\s]*([-\d.]+)\s*dB",
            re.IGNORECASE,
        )

        for line in output.splitlines():
            match = pci_pattern.search(line)
            if not match:
                continue

            pci = int(match.group(1))
            earfcn = int(match.group(2))
            freq = earfcn_to_freq(earfcn)
            band = earfcn_to_band(earfcn)

            # Try to get power from same or nearby line
            power_match = power_pattern.search(line)
            rssi = int(float(power_match.group(1))) if power_match else -100

            tower = CellTower(
                cell_id=str(pci),
                technology="LTE",
                earfcn=earfcn,
                pci=pci,
                frequency_mhz=freq,
                rssi=rssi,
                band=f"Band {band}" if band else "",
                metadata={"source": "srsRAN"},
            )
            towers.append(tower)
            log.info(
                "LTE eNodeB: PCI=%d EARFCN=%d %.1f MHz Band %d %d dBm",
                pci, earfcn, freq, band, rssi,
            )

        return towers
