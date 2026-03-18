"""Main cellular scanner orchestrator for CellGuard.

Coordinates GSM (gr-gsm + RTL-SDR), LTE (srsRAN + HackRF), and
5G NR (srsRAN nr_cell_search / mmcli) sub-scanners in a background
thread, aggregates discovered cell towers, and provides callbacks for
real-time updates.

Also provides ``save_baseline`` / ``load_baseline`` helpers that
persist to/from a JSON file and to the honeysnatch database.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from honeysnatch.cellular.models import CellTower, lookup_operator
from honeysnatch.utils.logger import get_logger

log = get_logger("cellular.scanner")


class CellularScanner:
    """Multi-technology cellular scanner.

    Orchestrates GSM, LTE, and 5G NR scanning backends.
    All discovered towers are available via ``get_towers()``.
    Subscribe to tower events with ``on_tower_found`` and
    ``on_rogue_alert`` callbacks.

    Baseline support
    ----------------
    Call ``save_baseline(path)`` after a clean scan to persist a
    known-good tower set.  On subsequent runs, ``load_baseline(path)``
    feeds the :class:`~honeysnatch.cellular.detector.RogueBaseStationDetector`
    so anomalies are flagged automatically.
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
        nr_bands: Optional[list[str]] = None,
        scan_interval: float = 30.0,
        baseline_path: str = "",
        on_tower_found: Optional[Callable[[CellTower], None]] = None,
        on_rogue_alert: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self.rtlsdr_device = rtlsdr_device
        self.hackrf_device = hackrf_device
        self.scan_gsm = scan_gsm
        self.scan_lte = scan_lte
        self.scan_5g = scan_5g
        self.gsm_bands = gsm_bands or ["GSM900", "GSM1800"]
        self.lte_bands = lte_bands or [2, 4, 5, 7, 12, 13, 66, 71]
        self.nr_bands = nr_bands or ["n78", "n71"]
        self.scan_interval = scan_interval
        self.on_tower_found = on_tower_found
        self.on_rogue_alert = on_rogue_alert

        self._towers: dict[str, CellTower] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._scan_count = 0

        # Rogue detection
        self._detector = None
        if baseline_path:
            self._init_detector(baseline_path)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def tower_count(self) -> int:
        return len(self._towers)

    @property
    def scan_count(self) -> int:
        return self._scan_count

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_towers(self) -> list[CellTower]:
        """Return a snapshot of all discovered cell towers."""
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
        log.info(
            "Cellular scanner started (GSM=%s, LTE=%s, 5G=%s)",
            self.scan_gsm, self.scan_lte, self.scan_5g,
        )

    def stop(self) -> None:
        """Stop scanning and wait for the thread to exit."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=15)
            self._thread = None
        log.info(
            "Cellular scanner stopped. Towers: %d  Scans: %d",
            len(self._towers), self._scan_count,
        )

    # ------------------------------------------------------------------
    # Baseline management
    # ------------------------------------------------------------------

    def save_baseline(self, path: str) -> None:
        """Persist current towers to a JSON baseline file.

        Args:
            path: Destination file path (e.g. ``baseline.json``).
        """
        from honeysnatch.cellular.detector import RogueBaseStationDetector
        detector = RogueBaseStationDetector()
        towers = self.get_towers()
        detector.save_baseline(towers, path)
        log.info("Baseline saved: %d towers → %s", len(towers), path)

    def load_baseline(self, path: str) -> None:
        """Load a previously saved baseline and enable rogue detection.

        Args:
            path: Path to the JSON baseline file.
        """
        self._init_detector(path)
        log.info("Baseline loaded from %s", path)

    def save_baseline_to_db(self, db_manager, session_id: str) -> int:
        """Persist current towers to the honeysnatch database.

        Args:
            db_manager: A :class:`~honeysnatch.db.database.DatabaseManager` instance.
            session_id: The active scan session ID.

        Returns:
            Number of towers saved.
        """
        towers = self.get_towers()
        for tower in towers:
            db_manager.save_cell_tower(session_id, tower)
        log.info("Saved %d towers to database session %s", len(towers), session_id)
        return len(towers)

    # ------------------------------------------------------------------
    # Internal scan loop
    # ------------------------------------------------------------------

    def _scan_loop(self) -> None:
        """Main scan loop — runs one cycle of GSM / LTE / 5G per interval."""
        while self._running:
            scan_start = time.time()
            current_scan: list[CellTower] = []

            try:
                if self.scan_gsm:
                    gsm_towers = self._run_gsm_scan()
                    current_scan.extend(gsm_towers)

                if not self._running:
                    break

                if self.scan_lte:
                    lte_towers = self._run_lte_scan()
                    current_scan.extend(lte_towers)

                if not self._running:
                    break

                if self.scan_5g:
                    nr_towers = self._run_nr_scan()
                    current_scan.extend(nr_towers)

                self._scan_count += 1

                # Update detector with this scan's tower list
                if self._detector:
                    self._detector.update_previous_scan(current_scan)

            except Exception as exc:
                log.error("Scan cycle error: %s", exc)

            # Wait for the remainder of the scan interval
            elapsed = time.time() - scan_start
            remaining = max(0.0, self.scan_interval - elapsed)
            deadline = time.time() + remaining
            while self._running and time.time() < deadline:
                time.sleep(0.1)

    def _run_gsm_scan(self) -> list[CellTower]:
        """Execute a GSM scan and register results."""
        from honeysnatch.cellular.gsm_scanner import GsmScanner
        scanner = GsmScanner(rtlsdr_device=self.rtlsdr_device)
        towers = scanner.scan(bands=self.gsm_bands)
        for tower in towers:
            self._add_tower(tower)
        return towers

    def _run_lte_scan(self) -> list[CellTower]:
        """Execute an LTE scan and register results."""
        from honeysnatch.cellular.lte_scanner import LteScanner
        scanner = LteScanner(device_name="hackrf", device_args=self.hackrf_device)
        towers = scanner.scan(bands=self.lte_bands)
        for tower in towers:
            self._add_tower(tower)
        return towers

    def _run_nr_scan(self) -> list[CellTower]:
        """Execute a 5G NR scan and register results."""
        from honeysnatch.cellular.nr_scanner import NrScanner
        scanner = NrScanner(device_name="hackrf", device_args=self.hackrf_device)
        towers = scanner.scan(bands=self.nr_bands)
        for tower in towers:
            self._add_tower(tower)
        return towers

    # ------------------------------------------------------------------
    # Tower registry
    # ------------------------------------------------------------------

    def _add_tower(self, tower: CellTower) -> None:
        """Add or update a tower; fire callbacks and rogue checks."""
        uid = tower.unique_id
        is_new = False

        with self._lock:
            if uid in self._towers:
                self._towers[uid].update(tower.rssi, tower.position)
            else:
                self._towers[uid] = tower
                is_new = True

        if is_new:
            log.info(
                "New %s tower: %s CID=%s %.1f MHz %d dBm",
                tower.technology, tower.plmn,
                tower.cell_id, tower.frequency_mhz, tower.rssi,
            )
            if self.on_tower_found:
                try:
                    self.on_tower_found(tower)
                except Exception as exc:
                    log.error("on_tower_found callback error: %s", exc)

        # Rogue check regardless of is_new
        if self._detector:
            alerts = self._detector.check_tower(tower)
            for alert in alerts:
                log.warning("ROGUE ALERT [%s]: %s", alert.severity.upper(), alert.message)
                if self.on_rogue_alert:
                    try:
                        self.on_rogue_alert(alert.to_dict())
                    except Exception as exc:
                        log.error("on_rogue_alert callback error: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _init_detector(self, baseline_path: str) -> None:
        """Instantiate a RogueBaseStationDetector from a baseline file."""
        from honeysnatch.cellular.detector import RogueBaseStationDetector
        try:
            detector = RogueBaseStationDetector()
            detector.load_baseline_file(baseline_path)
            self._detector = detector
            log.info(
                "Rogue detector active: %d baseline towers",
                len(detector._baseline),
            )
        except Exception as exc:
            log.error("Failed to load baseline %s: %s", baseline_path, exc)
