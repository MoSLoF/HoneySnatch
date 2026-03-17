"""5G NR (New Radio) cell tower scanner for CellGuard.

Wraps srsRAN's cell_search with NR support, or FALCON/OWL if available,
to discover 5G NR gNodeBs. Falls back to parsing /proc or AT commands
on Android/modem-attached hosts when dedicated SDR tools are absent.

5G NR uses NR-ARFCN (gNB Absolute Radio Frequency Channel Number)
instead of EARFCN. Frequency formula:
  F_REF = F_REF-Offs + ΔF_Global × (N_REF – N_REF-Offs)
"""
from __future__ import annotations

import re
import subprocess
from typing import Optional

from flyinghoneysnitch.cellular.models import CellTower, lookup_operator
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("cellular.5g_nr")


# ---------------------------------------------------------------------------
# NR-ARFCN → frequency conversion (3GPP TS 38.104 Table 5.4.2.1-1)
# ---------------------------------------------------------------------------

# (F_REF-Offs MHz, ΔF_Global kHz, N_REF-Offs, N_REF range)
_NR_FREQ_RANGES = [
    (0.0,       5.0,   0,      599_999),   # 0–3000 MHz
    (3000.0,   15.0,   600_000, 2_016_666), # 3–24.25 GHz
    (24_250.08, 60.0, 2_016_667, 3_279_165), # 24.25–100 GHz
]


def nrarfcn_to_freq(nrarfcn: int) -> float:
    """Convert NR-ARFCN to downlink frequency in MHz."""
    for f_offs, df_global_khz, n_offs, n_max in _NR_FREQ_RANGES:
        if n_offs <= nrarfcn <= n_max:
            return f_offs + (df_global_khz / 1000.0) * (nrarfcn - n_offs)
    return 0.0


def freq_to_nr_band(freq_mhz: float) -> str:
    """Return an approximate NR band label from frequency."""
    # Simplified FR1 / FR2 band map (common deployments)
    fr1_bands = [
        (600,  700,  "n71"),
        (700,  900,  "n12/n13/n14"),
        (850,  900,  "n5/n26"),
        (900,  960,  "n8"),
        (1700, 1800, "n3"),
        (1900, 2000, "n2/n25"),
        (2100, 2200, "n1"),
        (2300, 2400, "n40"),
        (2500, 2700, "n7/n41"),
        (3300, 4200, "n77/n78"),
        (4400, 5000, "n79"),
    ]
    for lo, hi, band in fr1_bands:
        if lo <= freq_mhz <= hi:
            return band
    if freq_mhz >= 24_000:
        return "FR2 (mmWave)"
    return "Unknown NR"


# ---------------------------------------------------------------------------
# Default NR-ARFCNs to probe (representative values per common US/EU bands)
# ---------------------------------------------------------------------------

DEFAULT_NR_ARFCNS: dict[str, list[int]] = {
    "n71":  [123_400],   # 600 MHz T-Mobile US
    "n5":   [176_300],   # 850 MHz
    "n8":   [185_000],   # 900 MHz
    "n3":   [368_500],   # 1800 MHz
    "n2":   [393_000],   # 1900 MHz
    "n1":   [430_000],   # 2100 MHz
    "n78":  [634_240],   # 3.5 GHz mid-band (primary 5G band)
    "n77":  [660_000],   # 3.7-3.98 GHz CBRS
    "n260": [2_229_166], # 39 GHz mmWave
    "n261": [2_071_669], # 28 GHz mmWave
}


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class NrScanner:
    """5G NR gNodeB scanner.

    Attempts the following backends in order:
    1. srsRAN ``nr_cell_search`` (HackRF / USRP)
    2. srsRAN legacy ``cell_search`` with ``--rat nr`` flag
    3. AT command via /dev/modem or mmcli (passive, no SDR needed)
    """

    def __init__(self, device_name: str = "hackrf", device_args: str = "") -> None:
        self.device_name = device_name
        self.device_args = device_args

    def scan(self, bands: Optional[list[str]] = None) -> list[CellTower]:
        """Scan for 5G NR gNodeBs.

        Args:
            bands: NR band labels to scan (e.g. ["n78", "n71"]).
                   Defaults to DEFAULT_NR_ARFCNS keys.

        Returns:
            List of discovered CellTower objects.
        """
        target_bands = bands or list(DEFAULT_NR_ARFCNS.keys())
        towers: list[CellTower] = []

        for band in target_bands:
            arfcns = DEFAULT_NR_ARFCNS.get(band, [])
            for arfcn in arfcns:
                try:
                    results = self._scan_arfcn(arfcn, band)
                    towers.extend(results)
                except Exception as exc:
                    log.debug("NR scan arfcn=%d band=%s error: %s", arfcn, band, exc)

        if not towers:
            log.debug("SDR NR scan yielded no results, trying AT command fallback")
            towers.extend(self._scan_at_fallback())

        return towers

    # ------------------------------------------------------------------
    # Backend: srsRAN nr_cell_search
    # ------------------------------------------------------------------

    def _scan_arfcn(self, arfcn: int, band: str) -> list[CellTower]:
        """Run srsRAN nr_cell_search for a single NR-ARFCN."""
        # Try srsRAN 5G-native tool first
        for binary in ("nr_cell_search", "cell_search"):
            towers = self._try_srsran(binary, arfcn, band)
            if towers is not None:
                return towers

        return []

    def _try_srsran(self, binary: str, arfcn: int, band: str) -> Optional[list[CellTower]]:
        cmd = [binary, f"--rf.device_name={self.device_name}"]
        if self.device_args:
            cmd.append(f"--rf.device_args={self.device_args}")

        if binary == "nr_cell_search":
            cmd.extend([f"--arfcn={arfcn}"])
        else:
            # Legacy cell_search with NR rat flag
            cmd.extend([f"--rat=nr", f"--nrarfcn={arfcn}"])

        log.info("Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            return None  # Binary not installed
        except subprocess.TimeoutExpired:
            log.warning("%s timed out for NR-ARFCN %d", binary, arfcn)
            return []

        return self._parse_nr_output(result.stdout + result.stderr, arfcn, band)

    def _parse_nr_output(self, output: str, arfcn: int, band: str) -> list[CellTower]:
        """Parse srsRAN NR cell search output."""
        towers = []
        freq = nrarfcn_to_freq(arfcn)

        # Pattern: "Found Cell: PCI=xxx" or "NR Cell: nci=xxx pci=xxx"
        pci_pattern = re.compile(
            r"(?:Found|NR)[^:]*:\s*.*?(?:PCI|pci)[=:\s]*(\d+)",
            re.IGNORECASE,
        )
        power_pattern = re.compile(
            r"(?:RSSI|RSRP|power)[=:\s]*([-\d.]+)\s*dB",
            re.IGNORECASE,
        )
        nci_pattern = re.compile(r"(?:NCI|nci)[=:\s]*(\d+)", re.IGNORECASE)

        for line in output.splitlines():
            m = pci_pattern.search(line)
            if not m:
                continue

            pci = int(m.group(1))
            nci_m = nci_pattern.search(line)
            cell_id = nci_m.group(1) if nci_m else str(pci)
            pwr_m = power_pattern.search(line)
            rssi = int(float(pwr_m.group(1))) if pwr_m else -100

            tower = CellTower(
                cell_id=cell_id,
                technology="5G_NR",
                pci=pci,
                earfcn=arfcn,           # reusing field for NR-ARFCN
                frequency_mhz=freq,
                rssi=rssi,
                band=f"{band} ({freq:.1f} MHz)",
                metadata={"source": "srsRAN_NR", "nrarfcn": arfcn},
            )
            towers.append(tower)
            log.info(
                "5G NR gNodeB: PCI=%d NCI=%s band=%s %.1f MHz %d dBm",
                pci, cell_id, band, freq, rssi,
            )

        return towers

    # ------------------------------------------------------------------
    # Backend: AT command / mmcli (no SDR required)
    # ------------------------------------------------------------------

    def _scan_at_fallback(self) -> list[CellTower]:
        """Passive 5G scan via ModemManager (mmcli) if a modem is present."""
        towers: list[CellTower] = []

        try:
            # List modems
            result = subprocess.run(
                ["mmcli", "-L"], capture_output=True, text=True, timeout=5,
            )
            modem_ids = re.findall(r"/org/freedesktop/ModemManager\d+/Modem/(\d+)", result.stdout)
        except FileNotFoundError:
            log.debug("mmcli not available (ModemManager not installed)")
            return towers
        except subprocess.TimeoutExpired:
            return towers

        for modem_id in modem_ids[:1]:  # Query first modem only
            try:
                result = subprocess.run(
                    ["mmcli", "-m", modem_id, "--location-get"],
                    capture_output=True, text=True, timeout=10,
                )
                towers.extend(self._parse_mmcli_location(result.stdout))
            except Exception as exc:
                log.debug("mmcli modem %s error: %s", modem_id, exc)

        return towers

    def _parse_mmcli_location(self, output: str) -> list[CellTower]:
        """Parse mmcli --location-get output for 5G NR serving cell."""
        towers: list[CellTower] = []

        # Look for 5GNR fields: mcc, mnc, tac, ci, nci, arfcn
        mcc  = self._extract(output, r"5gnr\s+mcc\s*:\s*(\d+)")
        mnc  = self._extract(output, r"5gnr\s+mnc\s*:\s*(\d+)")
        tac  = self._extract(output, r"5gnr\s+tac\s*:\s*(\S+)")
        ci   = self._extract(output, r"5gnr\s+(?:ci|nci)\s*:\s*(\S+)")
        arfcn_s = self._extract(output, r"5gnr\s+arfcn\s*:\s*(\d+)")
        rsrp = self._extract(output, r"5gnr\s+rsrp\s*:\s*([-\d.]+)")

        if not ci:
            return towers

        arfcn = int(arfcn_s) if arfcn_s else 0
        freq = nrarfcn_to_freq(arfcn) if arfcn else 0.0
        band = freq_to_nr_band(freq) if freq else ""
        operator = lookup_operator(mcc or "", mnc or "") if mcc and mnc else ""

        tower = CellTower(
            cell_id=ci,
            technology="5G_NR",
            mcc=mcc or "",
            mnc=mnc or "",
            tac=int(tac, 0) if tac else 0,
            earfcn=arfcn,
            frequency_mhz=freq,
            rssi=int(float(rsrp)) if rsrp else -120,
            band=band,
            operator=operator,
            metadata={"source": "mmcli"},
        )
        towers.append(tower)
        log.info(
            "5G NR serving cell (mmcli): NCI=%s MCC=%s MNC=%s band=%s",
            ci, mcc, mnc, band,
        )
        return towers

    @staticmethod
    def _extract(text: str, pattern: str) -> Optional[str]:
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1) if m else None
