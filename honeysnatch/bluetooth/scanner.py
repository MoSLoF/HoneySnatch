"""Passive Bluetooth scanner for BlueScout.

Provides passive Bluetooth and BLE device discovery via:
  1. Ubertooth One  (pyubertooth — full BLE packet access)
  2. Scapy BTLE     (with a monitor/injection-mode adapter)
  3. HCI fallback   (hcitool / bluetoothctl — active but lowest-privilege)

The scanner is fully event-driven.  Register a callback with
``on_device_found`` / ``on_device_updated`` to receive real-time
notifications.  All discovered devices are also accessible via
``get_devices()``.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Callable, Optional

from honeysnatch.bluetooth.ble_parser import parse_ble_advertisement
from honeysnatch.bluetooth.classifier import classify_bt_device
from honeysnatch.bluetooth.models import (
    BleAdvType,
    BluetoothDevice,
    BluetoothDeviceType,
)
from honeysnatch.core.models import GeoPosition
from honeysnatch.utils.logger import get_logger

log = get_logger("bluetooth.scanner")

# BLE advertising channel set
_BLE_ADV_CHANNELS = [37, 38, 39]


class BluetoothScanner:
    """Passive Bluetooth / BLE scanner.

    Usage::

        scanner = BluetoothScanner(on_device_found=my_callback)
        scanner.start()
        time.sleep(60)
        scanner.stop()
        devices = scanner.get_devices()
    """

    def __init__(
        self,
        ubertooth_device: str = "/dev/ubertooth0",
        hci_device: str = "hci0",
        use_scapy: bool = False,
        on_device_found: Optional[Callable[[BluetoothDevice], None]] = None,
        on_device_updated: Optional[Callable[[BluetoothDevice], None]] = None,
    ) -> None:
        self.ubertooth_device = ubertooth_device
        self.hci_device = hci_device
        self.use_scapy = use_scapy
        self._on_device_found = on_device_found
        self._on_device_updated = on_device_updated

        self._devices: dict[str, BluetoothDevice] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._packet_count = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def device_count(self) -> int:
        return len(self._devices)

    @property
    def packet_count(self) -> int:
        return self._packet_count

    def get_devices(self) -> list[BluetoothDevice]:
        """Return a snapshot of all discovered devices."""
        with self._lock:
            return list(self._devices.values())

    def get_device(self, address: str) -> Optional[BluetoothDevice]:
        """Return a device by address, or None."""
        with self._lock:
            return self._devices.get(address.lower())

    def start(self) -> None:
        """Start passive scanning in a background thread."""
        if self._running:
            log.warning("BluetoothScanner already running")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._scan_loop,
            name="BluetoothScanner",
            daemon=True,
        )
        self._thread.start()
        log.info("Bluetooth scanner started")

    def stop(self) -> None:
        """Stop scanning and wait for the background thread to exit."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        log.info(
            "Bluetooth scanner stopped. Devices: %d  Packets: %d",
            self.device_count, self.packet_count,
        )

    # ------------------------------------------------------------------
    # Internal scan loop — tries backends in priority order
    # ------------------------------------------------------------------

    def _scan_loop(self) -> None:
        try:
            if self.use_scapy:
                log.info("Trying Scapy BTLE backend")
                self._scan_scapy()
                return
        except Exception as exc:
            log.debug("Scapy BTLE backend failed: %s", exc)

        try:
            log.info("Trying Ubertooth backend on %s", self.ubertooth_device)
            self._scan_ubertooth()
            return
        except (ImportError, Exception) as exc:
            log.info("Ubertooth unavailable (%s), falling back to HCI", exc)

        self._scan_hci_fallback()

    # ------------------------------------------------------------------
    # Backend: Scapy BTLE
    # ------------------------------------------------------------------

    def _scan_scapy(self) -> None:
        """Scan using Scapy's BTLE layer (requires a compatible adapter in monitor mode)."""
        from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_SCAN_RSP
        from scapy.all import sniff

        def _handle(pkt):
            self._packet_count += 1
            try:
                if BTLE_ADV in pkt:
                    adv_layer = pkt[BTLE_ADV]
                    addr = getattr(adv_layer, "AdvA", None) or getattr(pkt, "src", None)
                    if not addr:
                        return
                    raw = bytes(adv_layer.payload) if adv_layer.payload else b""
                    adv_type = _scapy_pdu_to_type(adv_layer.PDU_type if hasattr(adv_layer, "PDU_type") else 0xFF)
                    advertisement = parse_ble_advertisement(raw, adv_type)
                    rssi = getattr(pkt, "dBm_AntSignal", -100) or -100
                    self._add_or_update(
                        address=addr,
                        rssi=int(rssi),
                        device_type=BluetoothDeviceType.BLE,
                        advertisement=advertisement,
                    )
            except Exception as exc:
                log.debug("Scapy BTLE packet error: %s", exc)

        sniff(
            iface=self.hci_device,
            prn=_handle,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    # ------------------------------------------------------------------
    # Backend: Ubertooth
    # ------------------------------------------------------------------

    def _scan_ubertooth(self) -> None:
        """Scan using Ubertooth One via pyubertooth."""
        from pyubertooth.ubertooth import Ubertooth  # type: ignore

        ut = Ubertooth(device=self.ubertooth_device)

        # Hop through BLE advertising channels
        channel_idx = 0
        while self._running:
            ch = _BLE_ADV_CHANNELS[channel_idx % len(_BLE_ADV_CHANNELS)]
            try:
                ut.set_channel(ch)
                packets = ut.rx_bt()
                for pkt in packets:
                    self._packet_count += 1
                    self._process_ubertooth_packet(pkt)
            except Exception as exc:
                log.debug("Ubertooth rx error on ch%d: %s", ch, exc)
                time.sleep(0.05)
            channel_idx += 1

        try:
            ut.close()
        except Exception:
            pass

    def _process_ubertooth_packet(self, pkt) -> None:
        """Convert a raw Ubertooth packet into a BluetoothDevice update."""
        try:
            raw_addr = getattr(pkt, "addr", None)
            if not raw_addr:
                return

            if isinstance(raw_addr, (bytes, bytearray)):
                address = ":".join(f"{b:02x}" for b in raw_addr)
            else:
                address = str(raw_addr)

            rssi = int(getattr(pkt, "rssi", -100) or -100)

            # Try to pull raw AD payload
            raw_ad = getattr(pkt, "data", b"") or b""
            advertisement = None
            if raw_ad:
                advertisement = parse_ble_advertisement(bytes(raw_ad))

            self._add_or_update(
                address=address,
                rssi=rssi,
                device_type=BluetoothDeviceType.BLE,
                advertisement=advertisement,
            )
        except Exception as exc:
            log.debug("Ubertooth packet processing error: %s", exc)

    # ------------------------------------------------------------------
    # Backend: HCI fallback (hcitool)
    # ------------------------------------------------------------------

    def _scan_hci_fallback(self) -> None:
        """Fallback scanner using Linux HCI tools (active scanning)."""
        import subprocess

        log.info("Using HCI fallback scanner on %s", self.hci_device)

        while self._running:
            # --- Classic BT discovery ---
            try:
                result = subprocess.run(
                    ["hcitool", "-i", self.hci_device, "scan", "--flush"],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.strip().splitlines()[1:]:
                    parts = line.strip().split("\t")
                    if len(parts) >= 1:
                        address = parts[0].strip()
                        name = parts[1].strip() if len(parts) > 1 else ""
                        self._add_or_update(address, device_type=BluetoothDeviceType.CLASSIC, name=name)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # --- BLE scan (LE scan enable) ---
            try:
                # Enable LE scanning
                subprocess.run(
                    ["hcitool", "-i", self.hci_device, "lescan", "--passive"],
                    capture_output=True, text=True, timeout=8,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Read results via bluetoothctl if available
            try:
                result = subprocess.run(
                    ["bluetoothctl", "devices"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.strip().splitlines():
                    # "Device AA:BB:CC:DD:EE:FF DeviceName"
                    parts = line.strip().split(" ", 2)
                    if len(parts) >= 2 and parts[0] == "Device":
                        address = parts[1]
                        name = parts[2] if len(parts) > 2 else ""
                        self._add_or_update(address, device_type=BluetoothDeviceType.BLE, name=name)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            time.sleep(3)

    # ------------------------------------------------------------------
    # Device registry
    # ------------------------------------------------------------------

    def _add_or_update(
        self,
        address: str,
        rssi: int = -100,
        device_type: BluetoothDeviceType = BluetoothDeviceType.UNKNOWN,
        name: str = "",
        position: Optional[GeoPosition] = None,
        advertisement=None,
    ) -> None:
        """Add a new device or update an existing one; fire callbacks."""
        addr_norm = address.lower()

        with self._lock:
            is_new = addr_norm not in self._devices

            if is_new:
                device = BluetoothDevice(
                    address=addr_norm,
                    device_type=device_type,
                    rssi=rssi,
                    name=name,
                    advertisement=advertisement,
                )
                classify_bt_device(device)
                self._devices[addr_norm] = device
                log.info(
                    "BT device found: %s  %-8s  %-30s  %d dBm  [%s]",
                    addr_norm,
                    device.device_type.value,
                    device.name or device.company_name or device.manufacturer or "?",
                    rssi,
                    device.risk,
                )
            else:
                device = self._devices[addr_norm]
                device.update(rssi, position, advertisement)
                if name and not device.name:
                    device.name = name
                    device.device_type = device_type
                classify_bt_device(device)

        # Fire callbacks outside the lock
        if is_new:
            if self._on_device_found:
                try:
                    self._on_device_found(device)
                except Exception as exc:
                    log.error("on_device_found callback error: %s", exc)
        else:
            if self._on_device_updated:
                try:
                    self._on_device_updated(device)
                except Exception as exc:
                    log.error("on_device_updated callback error: %s", exc)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _scapy_pdu_to_type(pdu_type: int) -> BleAdvType:
    """Map Scapy BTLE PDU type integer to BleAdvType enum."""
    mapping = {
        0: BleAdvType.ADV_IND,
        1: BleAdvType.ADV_DIRECT_IND,
        2: BleAdvType.ADV_NONCONN_IND,
        4: BleAdvType.SCAN_RSP,
        6: BleAdvType.ADV_SCAN_IND,
    }
    return mapping.get(pdu_type, BleAdvType.UNKNOWN)
