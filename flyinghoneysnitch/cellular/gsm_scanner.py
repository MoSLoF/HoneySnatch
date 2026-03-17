"""GSM/2G cell tower scanning using gr-gsm and RTL-SDR.

Wraps the grgsm_scanner tool to discover nearby GSM base transceiver
stations (BTS) and extract cell parameters (ARFCN, MCC, MNC, LAC, CID).
Falls back to kalibrate-rtl for basic frequency scanning if gr-gsm
is not available.
"""

from __future__ import annotations

import re
import subprocess
from typing import Optional

from flyinghoneysnitch.cellular.models import CellTower, arfcn_to_freq, lookup_operator
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("cellular.gsm")


class GsmScanner:
    """GSM cell tower scanner using gr-gsm + RTL-SDR."""

    def __init__(self, rtlsdr_device: int = 0) -> None:
        self.rtlsdr_device = rtlsdr_device

    def scan(self, bands: Optional[list[str]] = None) -> list[CellTower]:
        """Scan for GSM base stations.

        Args:
            bands: GSM bands to scan (e.g., ["GSM900", "GSM1800"]).
                   Defaults to GSM900 + GSM1800 if None.

        Returns:
            List of discovered CellTower objects.
        """
        if bands is None:
            bands = ["GSM900", "GSM1800"]

        try:
            return self._scan_grgsm(bands)
        except FileNotFoundError:
            log.warning("grgsm_scanner not found, falling back to kalibrate-rtl")
            return self._scan_kalibrate(bands)
        except Exception as e:
            log.error("GSM scan failed: %s", e)
            return []

    def _scan_grgsm(self, bands: list[str]) -> list[CellTower]:
        """Scan using grgsm_scanner."""
        cmd = ["grgsm_scanner"]
        for band in bands:
            cmd.extend(["-b", band])
        cmd.extend(["--args", f"rtl={self.rtlsdr_device}"])

        log.info("Running: %s", " ".join(cmd))
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )

        if result.returncode != 0:
            log.error("grgsm_scanner failed: %s", result.stderr.strip())
            return []

        return self._parse_grgsm_output(result.stdout)

    def _parse_grgsm_output(self, output: str) -> list[CellTower]:
        """Parse grgsm_scanner output into CellTower objects.

        Expected output format (one line per cell):
            ARFCN:  xxx, Freq:  xxx.xM, CID: xxxxx, LAC: xxxxx, MCC: xxx, MNC: xx, Pwr: -xx
        """
        towers = []

        # Pattern matches grgsm_scanner output lines
        pattern = re.compile(
            r"ARFCN:\s*(\d+),\s*Freq:\s*([\d.]+)M?,\s*"
            r"CID:\s*(\d+),\s*LAC:\s*(\d+),\s*"
            r"MCC:\s*(\d+),\s*MNC:\s*(\d+),\s*"
            r"Pwr:\s*([-\d.]+)"
        )

        for line in output.splitlines():
            match = pattern.search(line)
            if not match:
                continue

            arfcn = int(match.group(1))
            freq = float(match.group(2))
            cid = match.group(3)
            lac = int(match.group(4))
            mcc = match.group(5)
            mnc = match.group(6)
            power = float(match.group(7))

            operator = lookup_operator(mcc, mnc)

            tower = CellTower(
                cell_id=cid,
                technology="GSM",
                mcc=mcc,
                mnc=mnc,
                lac=lac,
                arfcn=arfcn,
                frequency_mhz=freq if freq > 0 else arfcn_to_freq(arfcn),
                rssi=int(power),
                power=power,
                band=self._arfcn_to_band_name(arfcn),
                operator=operator,
            )
            towers.append(tower)
            log.info(
                "GSM tower: CID=%s MCC=%s MNC=%s LAC=%d ARFCN=%d %.1f MHz %s dBm %s",
                cid, mcc, mnc, lac, arfcn, tower.frequency_mhz, power,
                operator or "Unknown",
            )

        return towers

    def _scan_kalibrate(self, bands: list[str]) -> list[CellTower]:
        """Fallback: scan using kalibrate-rtl (kal).

        Only finds active frequencies — no cell parameters extracted.
        """
        towers = []
        band_map = {"GSM850": "850", "GSM900": "GSM900", "GSM1800": "DCS", "GSM1900": "PCS"}

        for band in bands:
            kal_band = band_map.get(band, band)
            try:
                result = subprocess.run(
                    ["kal", "-s", kal_band, "-d", str(self.rtlsdr_device)],
                    capture_output=True, text=True, timeout=60,
                )

                if result.returncode != 0:
                    continue

                # Parse kal output: "chan: XX (XXX.XMHz + XXXHz)  power: XXXXX.XX"
                kal_pattern = re.compile(
                    r"chan:\s*(\d+)\s*\(([\d.]+)MHz\s*[+-]\s*[\d.]+Hz\)\s*power:\s*([\d.]+)"
                )

                for line in result.stdout.splitlines():
                    match = kal_pattern.search(line)
                    if match:
                        arfcn = int(match.group(1))
                        freq = float(match.group(2))
                        power = float(match.group(3))

                        tower = CellTower(
                            cell_id=f"kal-{arfcn}",
                            technology="GSM",
                            arfcn=arfcn,
                            frequency_mhz=freq,
                            power=power,
                            band=band,
                            metadata={"source": "kalibrate-rtl"},
                        )
                        towers.append(tower)

            except FileNotFoundError:
                log.error("kalibrate-rtl (kal) not found. Install: sudo apt install kalibrate-rtl")
                break
            except subprocess.TimeoutExpired:
                log.warning("kal scan timed out for band %s", band)

        return towers

    @staticmethod
    def _arfcn_to_band_name(arfcn: int) -> str:
        """Determine GSM band name from ARFCN."""
        if 0 <= arfcn <= 124:
            return "GSM900"
        elif 128 <= arfcn <= 251:
            return "GSM850"
        elif 512 <= arfcn <= 885:
            return "GSM1800"
        elif 512 <= arfcn <= 810:
            return "GSM1900"
        return "Unknown"
