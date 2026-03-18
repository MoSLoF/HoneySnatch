"""Pcap capture session management for honeysnatch.

Records raw packets to pcap files for later analysis and evidence preservation.
"""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from scapy.all import PcapWriter, sniff
from scapy.packet import Packet

from honeysnatch.utils.logger import get_logger

log = get_logger("capture")


class PcapCapture:
    """Records packets to a pcap file alongside live scanning.

    Can be used to save all captured traffic for post-hoc analysis
    or compliance/evidence requirements.
    """

    def __init__(
        self,
        output_dir: str,
        prefix: str = "fhb_capture",
        max_file_size_mb: int = 100,
    ) -> None:
        """
        Args:
            output_dir: Directory to store pcap files.
            prefix: Filename prefix for pcap files.
            max_file_size_mb: Maximum file size before rotating.
        """
        self.output_dir = Path(output_dir)
        self.prefix = prefix
        self.max_file_size_mb = max_file_size_mb

        self._writer: Optional[PcapWriter] = None
        self._current_file: Optional[Path] = None
        self._packet_count = 0
        self._file_index = 0
        self._lock = threading.Lock()
        self._running = False

    @property
    def is_recording(self) -> bool:
        """Return True if packet capture is currently active."""
        return self._running

    @property
    def current_file(self) -> Optional[str]:
        """Return the path to the pcap file currently being written, or None."""
        return str(self._current_file) if self._current_file else None

    @property
    def packet_count(self) -> int:
        """Return the total number of packets written in this capture."""
        return self._packet_count

    def start(self) -> str:
        """Start recording packets to a pcap file.

        Returns:
            Path to the pcap file being written.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.prefix}_{timestamp}.pcap"
        self._current_file = self.output_dir / filename

        self._writer = PcapWriter(
            str(self._current_file),
            append=False,
            sync=True,
        )
        self._running = True
        self._packet_count = 0
        self._file_index = 0

        log.info("Pcap capture started: %s", self._current_file)
        return str(self._current_file)

    def stop(self) -> Optional[str]:
        """Stop recording and close the pcap file.

        Returns:
            Path to the completed pcap file, or None if not recording.
        """
        if not self._running:
            return None

        self._running = False
        filepath = str(self._current_file) if self._current_file else None

        with self._lock:
            if self._writer:
                self._writer.close()
                self._writer = None

        log.info(
            "Pcap capture stopped: %s (%d packets)",
            filepath, self._packet_count,
        )
        return filepath

    def write_packet(self, packet: Packet) -> None:
        """Write a single packet to the pcap file.

        Thread-safe. Handles file rotation if max size is exceeded.
        """
        if not self._running or not self._writer:
            return

        with self._lock:
            try:
                self._writer.write(packet)
                self._packet_count += 1

                # Check file size for rotation
                if self._current_file and self._packet_count % 1000 == 0:
                    size_mb = self._current_file.stat().st_size / (1024 * 1024)
                    if size_mb >= self.max_file_size_mb:
                        self._rotate_file()

            except Exception as e:
                log.error("Failed to write packet: %s", e)

    def _rotate_file(self) -> None:
        """Rotate to a new pcap file when the current one is too large."""
        if self._writer:
            self._writer.close()

        self._file_index += 1
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.prefix}_{timestamp}_{self._file_index:03d}.pcap"
        self._current_file = self.output_dir / filename

        self._writer = PcapWriter(
            str(self._current_file),
            append=False,
            sync=True,
        )
        log.info("Rotated pcap to: %s", self._current_file)


def load_pcap(filepath: str) -> list[Packet]:
    """Load packets from a pcap file for analysis.

    Args:
        filepath: Path to the pcap file.

    Returns:
        List of scapy packets.
    """
    from scapy.all import rdpcap

    log.info("Loading pcap: %s", filepath)
    packets = rdpcap(filepath)
    log.info("Loaded %d packets from %s", len(packets), filepath)
    return list(packets)
