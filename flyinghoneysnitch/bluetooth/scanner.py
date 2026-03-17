"""Bluetooth passive scanner using Ubertooth One for BlueScout.

Provides passive Bluetooth device discovery without active scanning
or pairing, using the Ubertooth One hardware.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Callable, Optional

from flyinghoneysnitch.bluetooth.models import BluetoothDevice, classify_device
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("bluetooth.scanner")


class BluetoothScanner:
    """Passive Bluetooth scanner using Ubertooth One.

    Monitors Bluetooth traffic in promiscuous mode to discover
    nearby devices without active scanning.
    """

    def __init__(
        self,
        device: str = "/dev/ubertooth0",
        on_device_found: Optional[Callable[[BluetoothDevice], None]] = None,
    ) -> None:
        self.device = device
        self.on_device_found = on_device_found

        self._devices: dict[str, BluetoothDevice] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    def get_devices(self) -> list[BluetoothDevice]:
        """Get all discovered devices."""
        with self._lock:
            return list(self._devices.values())

    def start(self) -> None:
        """Start passive Bluetooth scanning."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._scan_loop,
            name="BluetoothScanner",
            daemon=True,
        )
        self._thread.start()
        log.info("Bluetooth scanner started on %s", self.device)

    def stop(self) -> None:
        """Stop scanning."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        log.info("Bluetooth scanner stopped. Devices found: %d", len(self._devices))

    def _scan_loop(self) -> None:
        """Main scanning loop."""
        try:
            # Try to use pyubertooth
            self._scan_ubertooth()
        except ImportError:
            log.warning("pyubertooth not available, falling back to HCI scanning")
            self._scan_hci_fallback()
        except Exception as e:
            log.error("Bluetooth scan error: %s", e)

    def _scan_ubertooth(self) -> None:
        """Scan using Ubertooth One via pyubertooth."""
        try:
            from pyubertooth.ubertooth import Ubertooth

            ut = Ubertooth(device=self.device)
            ut.set_channel(37)  # BLE advertising channel

            while self._running:
                try:
                    packets = ut.rx_bt()
                    for pkt in packets:
                        self._process_ubertooth_packet(pkt)
                except Exception as e:
                    log.debug("Ubertooth rx error: %s", e)
                    time.sleep(0.1)

            ut.close()

        except Exception as e:
            log.error("Ubertooth scan failed: %s", e)
            raise

    def _scan_hci_fallback(self) -> None:
        """Fallback Bluetooth scanning using Linux HCI tools."""
        import subprocess

        log.info("Using HCI fallback scanning (hcitool)")

        while self._running:
            try:
                # Use hcitool for basic device discovery
                result = subprocess.run(
                    ["hcitool", "scan", "--flush"],
                    capture_output=True, text=True, timeout=15,
                )

                if result.returncode == 0:
                    for line in result.stdout.strip().splitlines()[1:]:
                        parts = line.strip().split("\t")
                        if len(parts) >= 2:
                            address = parts[0].strip()
                            name = parts[1].strip() if len(parts) > 1 else ""
                            self._add_device(address, name=name, device_type="Classic")

                # Also try BLE scan
                result = subprocess.run(
                    ["hcitool", "lescan", "--duplicates"],
                    capture_output=True, text=True, timeout=10,
                )

                if result.returncode == 0:
                    for line in result.stdout.strip().splitlines()[1:]:
                        parts = line.strip().split(" ", 1)
                        if len(parts) >= 1:
                            address = parts[0].strip()
                            name = parts[1].strip() if len(parts) > 1 else ""
                            self._add_device(address, name=name, device_type="BLE")

            except subprocess.TimeoutExpired:
                pass
            except FileNotFoundError:
                log.error("hcitool not found. Install bluez: sudo apt install bluez")
                break
            except Exception as e:
                log.debug("HCI scan error: %s", e)

            time.sleep(2)

    def _process_ubertooth_packet(self, packet) -> None:
        """Process a raw Ubertooth packet."""
        try:
            if hasattr(packet, "addr") and packet.addr:
                address = ":".join(f"{b:02x}" for b in packet.addr)
                rssi = getattr(packet, "rssi", -100)
                self._add_device(address, rssi=rssi, device_type="BLE")
        except Exception as e:
            log.debug("Failed to process Ubertooth packet: %s", e)

    def _add_device(
        self,
        address: str,
        rssi: int = -100,
        name: str = "",
        device_type: str = "Unknown",
    ) -> None:
        """Add or update a discovered device."""
        with self._lock:
            if address in self._devices:
                dev = self._devices[address]
                dev.update(rssi)
                if name and not dev.name:
                    dev.name = name
            else:
                dev = BluetoothDevice(
                    address=address,
                    device_type=device_type,
                    rssi=rssi,
                    name=name,
                )
                self._devices[address] = dev
                log.info("BT device found: %s %s (%s)", address, name, device_type)

                if self.on_device_found:
                    try:
                        self.on_device_found(dev)
                    except Exception as e:
                        log.error("Device callback error: %s", e)
