"""Main cellular scanner orchestrator for CellGuard.

Coordinates GSM and LTE sub-scanners in a background thread,
aggregates discovered cell towers, and provides callbacks for
real-time updates.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from flyinghoneysnitch.cellular.models import CellTower
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("cellular.scanner")


class CellularScanner:
    """Multi-technology cellular scanner.

    Orchestrates GSM (gr-gsm + RTL-SDR) and LTE (srsRAN + HackRF)
    scanning backends to discover nearby cell towers.
    """

    def __init__(
        self,
        rtlsdr_device: int = 0,
        hackrf_device: str = "",
        scan_gsm: bool = True,
        scan_lte: bool = True,
        scan_5g: bool = False,
        gsm_bands: Optional[list[str]] = None,
        lte_bands: Optional[list[int]] = None,
        scan_interval: float = 30.0,
        on_tower_found: Optional[Callable[[CellTower], None]] = None,
    ) -> None:
        self.rtlsdr_device = rtlsdr_device
        self.hackrf_device = hackrf_device
        self.scan_gsm = scan_gsm
        self.scan_lte = scan_lte
        self.scan_5g = scan_5g
        self.gsm_bands = gsm_bands or ["GSM900", "GSM1800"]
        self.lte_bands = lte_bands or [2, 4, 5, 7, 12, 13, 66, 71]
        self.scan_interval = scan_interval
        self.on_tower_found = on_tower_found

        self._towers: dict[str, CellTower] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._scan_count = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def tower_count(self) -> int:
        return len(self._towers)

    @property
    def scan_count(self) -> int:
        return self._scan_count

    def get_towers(self) -> list[CellTower]:
        """Get all discovered cell towers."""
        with self._lock:
            return list(self._towers.values())

    def start(self) -> None:
        """Start cellular scanning in a background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._scan_loop,
            name="CellularScanner",
            daemon=True,
        )
        self._thread.start()
        log.info("Cellular scanner started (GSM=%s, LTE=%s)", self.scan_gsm, self.scan_lte)

    def stop(self) -> None:
        """Stop scanning."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=15)
            self._thread = None
        log.info("Cellular scanner stopped. Towers found: %d", len(self._towers))

    def _scan_loop(self) -> None:
        """Main scan loop — alternates between GSM and LTE scans."""
        while self._running:
            try:
                if self.scan_gsm:
                    self._run_gsm_scan()

                if not self._running:
                    break

                if self.scan_lte:
                    self._run_lte_scan()

                self._scan_count += 1

            except Exception as e:
                log.error("Scan cycle error: %s", e)

            # Wait between scan cycles
            for _ in range(int(self.scan_interval * 10)):
                if not self._running:
                    break
                time.sleep(0.1)

    def _run_gsm_scan(self) -> None:
        """Execute a GSM scan cycle."""
        from flyinghoneysnitch.cellular.gsm_scanner import GsmScanner

        scanner = GsmScanner(rtlsdr_device=self.rtlsdr_device)
        towers = scanner.scan(bands=self.gsm_bands)

        for tower in towers:
            self._add_tower(tower)

    def _run_lte_scan(self) -> None:
        """Execute an LTE scan cycle."""
        from flyinghoneysnitch.cellular.lte_scanner import LteScanner

        scanner = LteScanner(
            device_name="hackrf",
            device_args=self.hackrf_device,
        )
        towers = scanner.scan(bands=self.lte_bands)

        for tower in towers:
            self._add_tower(tower)

    def _add_tower(self, tower: CellTower) -> None:
        """Add or update a discovered tower."""
        uid = tower.unique_id
        is_new = False

        with self._lock:
            if uid in self._towers:
                existing = self._towers[uid]
                existing.update(tower.rssi, tower.position)
            else:
                self._towers[uid] = tower
                is_new = True

        if is_new:
            log.info(
                "New cell tower: %s %s CID=%s %s %.1f MHz",
                tower.technology, tower.plmn, tower.cell_id,
                tower.operator or "Unknown", tower.frequency_mhz,
            )
            if self.on_tower_found:
                try:
                    self.on_tower_found(tower)
                except Exception as e:
                    log.error("Tower callback error: %s", e)
