"""Passive WiFi scanner engine - the core of HoneyBadger.

Sniffs 802.11 frames in monitor mode, parses them, and maintains
a real-time view of discovered access points and clients.
Emits events for GUI/CLI consumers via callback registration.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Callable, Optional

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, RadioTap
from scapy.packet import Packet

from flyinghoneysnitch.core.channel_hopper import (
    CHANNELS_2_4GHZ,
    CHANNELS_5GHZ,
    ChannelHopper,
)
from flyinghoneysnitch.core.detector import HiddenNetworkDetector
from flyinghoneysnitch.core.models import (
    AccessPoint,
    Client,
    ScanEvent,
    ScanSession,
)
from flyinghoneysnitch.core.oui_lookup import lookup_vendor
from flyinghoneysnitch.core.packet_parser import parse_packet
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("scanner")


class WifiScanner:
    """Passive WiFi scanner using scapy in monitor mode.

    Provides real-time discovery of access points and clients by
    sniffing 802.11 management and data frames.

    Usage:
        scanner = WifiScanner("wlan0mon")
        scanner.on_event(my_callback)
        scanner.start()
        # ... scanning ...
        scanner.stop()
        session = scanner.session
    """

    def __init__(
        self,
        interface: str,
        channels: Optional[list[int]] = None,
        hop_interval: float = 0.5,
        scan_5ghz: bool = True,
        session_name: str = "",
    ) -> None:
        """
        Args:
            interface: Monitor-mode wireless interface.
            channels: Custom channel list. Defaults to 2.4 GHz (+ 5 GHz if enabled).
            hop_interval: Seconds between channel hops.
            scan_5ghz: Include 5 GHz channels in the default channel list.
            session_name: Name for this scan session.
        """
        self.interface = interface

        # Build channel list
        if channels:
            self._channels = channels
        else:
            self._channels = CHANNELS_2_4GHZ.copy()
            if scan_5ghz:
                self._channels.extend(CHANNELS_5GHZ)

        # Initialize session
        from uuid import uuid4
        self.session = ScanSession(
            session_id=uuid4().hex[:16],
            name=session_name or f"Scan {datetime.now():%Y-%m-%d %H:%M}",
            interface=interface,
            channels=self._channels,
        )

        # Components
        self._hopper = ChannelHopper(
            interface=interface,
            channels=self._channels,
            hop_interval=hop_interval,
            on_channel_change=self._on_channel_change,
        )
        self._detector = HiddenNetworkDetector()

        # State
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._callbacks: list[Callable[[ScanEvent], None]] = []
        self._current_channel = 0
        self._packet_count = 0
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        """Return True if the scanner is actively capturing packets."""
        return self._running

    @property
    def current_channel(self) -> int:
        """Return the WiFi channel currently being monitored."""
        return self._hopper.current_channel

    @property
    def packet_count(self) -> int:
        """Return the total number of packets processed so far."""
        return self._packet_count

    @property
    def ap_count(self) -> int:
        """Return the number of access points discovered."""
        return self.session.ap_count

    @property
    def client_count(self) -> int:
        """Return the number of client stations discovered."""
        return self.session.client_count

    @property
    def hidden_ap_count(self) -> int:
        """Return the number of hidden-SSID access points detected."""
        return self._detector.hidden_count

    def on_event(self, callback: Callable[[ScanEvent], None]) -> None:
        """Register a callback for scan events.

        Events emitted:
        - ap_found: New access point discovered
        - ap_updated: Existing AP signal/info updated
        - client_found: New client discovered
        - client_updated: Existing client updated
        - hidden_revealed: Hidden SSID resolved
        - scan_started: Scanning began
        - scan_stopped: Scanning ended
        - channel_changed: Channel hop occurred
        """
        self._callbacks.append(callback)

    def start(self) -> None:
        """Start passive WiFi scanning."""
        if self._running:
            log.warning("Scanner already running")
            return

        self._running = True
        self.session.start_time = datetime.now()

        # Start channel hopping
        self._hopper.start()

        # Start packet sniffing in a background thread
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            name="WifiScanner",
            daemon=True,
        )
        self._sniff_thread.start()

        self._emit_event(ScanEvent(event_type="scan_started"))
        log.info(
            "Scanner started on %s (%d channels)",
            self.interface, len(self._channels),
        )

    def stop(self) -> None:
        """Stop scanning and finalize the session."""
        if not self._running:
            return

        self._running = False
        self._hopper.stop()

        # Wait for sniff thread to finish
        if self._sniff_thread:
            self._sniff_thread.join(timeout=10)
            self._sniff_thread = None

        self.session.end_time = datetime.now()

        self._emit_event(ScanEvent(event_type="scan_stopped"))
        log.info(
            "Scanner stopped. APs: %d, Clients: %d, Packets: %d, Duration: %.0fs",
            self.ap_count, self.client_count, self._packet_count,
            self.session.duration_seconds,
        )

    def pin_channel(self, channel: int) -> None:
        """Pin scanning to a single channel."""
        self._hopper.pin_channel(channel)

    def resume_hopping(self) -> None:
        """Resume channel hopping after pinning."""
        self._hopper.set_channels(self._channels)

    def _sniff_loop(self) -> None:
        """Main packet capture loop using scapy."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            log.error("Sniff error: %s", e)
            self._running = False

    def _process_packet(self, packet: Packet) -> None:
        """Process a single captured packet."""
        self._packet_count += 1

        parsed = parse_packet(packet)
        if not parsed:
            return

        ptype = parsed["type"]

        with self._lock:
            if ptype == "beacon":
                self._handle_beacon(parsed["ap"])

            elif ptype == "probe_request":
                self._handle_probe_request(parsed["client"], parsed.get("ssid", ""))

            elif ptype == "probe_response":
                if parsed.get("ap"):
                    self._handle_beacon(parsed["ap"])
                if parsed.get("client"):
                    self._handle_client(parsed["client"])
                # Check for hidden SSID reveal
                if parsed.get("ap") and parsed["ap"].ssid:
                    revealed = self._detector.process_probe_response(
                        parsed["ap"].bssid, parsed["ap"].ssid
                    )
                    if revealed:
                        self._emit_event(ScanEvent(
                            event_type="hidden_revealed",
                            ap=parsed["ap"],
                            data={"ssid": revealed},
                        ))

            elif ptype == "association_request":
                client = parsed["client"]
                self._handle_client(client)
                if client.bssid and client.ssid:
                    revealed = self._detector.process_association(client.bssid, client.ssid)
                    if revealed:
                        self._emit_event(ScanEvent(
                            event_type="hidden_revealed",
                            data={"bssid": client.bssid, "ssid": revealed},
                        ))

            elif ptype == "data":
                if parsed.get("client"):
                    self._handle_client(parsed["client"])
                # Update AP data count
                bssid = parsed.get("bssid")
                if bssid and bssid in self.session.access_points:
                    self.session.access_points[bssid].data_count += 1

    def _handle_beacon(self, ap: AccessPoint) -> None:
        """Handle a parsed beacon/probe response for an AP."""
        # Resolve vendor
        if not ap.vendor:
            ap.vendor = lookup_vendor(ap.bssid)

        is_new = ap.bssid not in self.session.access_points

        # Check for hidden SSID
        self._detector.check_beacon(ap)

        # Add/update in session
        self.session.add_ap(ap)

        # Track AP's clients
        actual_ap = self.session.access_points[ap.bssid]

        if is_new:
            self._emit_event(ScanEvent(
                event_type="ap_found",
                ap=actual_ap,
            ))
        else:
            self._emit_event(ScanEvent(
                event_type="ap_updated",
                ap=actual_ap,
            ))

    def _handle_probe_request(self, client: Client, ssid: str) -> None:
        """Handle a probe request from a client."""
        if not client.vendor:
            client.vendor = lookup_vendor(client.mac)

        is_new = client.mac not in self.session.clients
        self.session.add_client(client)

        actual_client = self.session.clients[client.mac]

        if is_new:
            self._emit_event(ScanEvent(
                event_type="client_found",
                client=actual_client,
            ))
        else:
            self._emit_event(ScanEvent(
                event_type="client_updated",
                client=actual_client,
            ))

    def _handle_client(self, client: Client) -> None:
        """Handle a discovered client station."""
        if not client.vendor:
            client.vendor = lookup_vendor(client.mac)

        is_new = client.mac not in self.session.clients
        self.session.add_client(client)

        # Link client to AP
        if client.bssid and client.bssid in self.session.access_points:
            ap = self.session.access_points[client.bssid]
            if client.mac not in ap.clients:
                ap.clients.append(client.mac)

        actual_client = self.session.clients[client.mac]

        if is_new:
            self._emit_event(ScanEvent(
                event_type="client_found",
                client=actual_client,
            ))
        else:
            self._emit_event(ScanEvent(
                event_type="client_updated",
                client=actual_client,
            ))

    def _on_channel_change(self, channel: int) -> None:
        """Callback from channel hopper."""
        self._current_channel = channel
        self._emit_event(ScanEvent(
            event_type="channel_changed",
            data={"channel": channel},
        ))

    def _emit_event(self, event: ScanEvent) -> None:
        """Emit an event to all registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                log.error("Event callback error: %s", e)
