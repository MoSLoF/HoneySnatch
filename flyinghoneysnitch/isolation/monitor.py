"""Monitor mode interface management for isolation testing.

Provides monitor mode event loop, GTK injection capabilities,
and target frame filtering.

Refactored from AirSnitch's Monitor class.
"""
from __future__ import annotations

import select
import time
from typing import Optional, Callable

from flyinghoneysnitch.isolation.daemon import Daemon
from flyinghoneysnitch.isolation.libwifi.wifi import (
    log, STATUS, DEBUG, WARNING,
    MonitorSocket, set_monitor_mode, set_channel,
)


class Monitor(Daemon):
    """Monitor mode interface for passive frame capture and injection.

    Extends Daemon to provide monitor-mode specific functionality
    including GTK-based frame injection and target filtering.
    """

    def __init__(self, iface: str, channel: Optional[int] = None,
                 frequency: Optional[str] = None, **kwargs):
        super().__init__(iface, ap_mode=False, **kwargs)
        self.channel = channel
        self.frequency = frequency
        self.sock_mon: Optional[MonitorSocket] = None
        self.gtk: Optional[bytes] = None
        self.gtk_idx: int = 0

    def start_monitor(self) -> None:
        """Start monitor mode on the interface."""
        set_monitor_mode(self.iface)
        if self.channel:
            set_channel(self.iface, self.channel)
        self.sock_mon = MonitorSocket(type=0x0003, iface=self.iface)
        log(STATUS, f"Monitor mode started on {self.iface}")

    def set_gtk(self, gtk: bytes, idx: int = 0) -> None:
        """Set the GTK for frame injection."""
        self.gtk = gtk
        self.gtk_idx = idx

    def inject_mon(self, frame) -> None:
        """Inject a frame via the monitor interface."""
        if self.sock_mon:
            self.sock_mon.send(frame)

    def is_target_frame(self, frame, target_mac: str) -> bool:
        """Check if a frame involves the target MAC address."""
        if not frame:
            return False
        return (getattr(frame, 'addr1', None) == target_mac or
                getattr(frame, 'addr2', None) == target_mac)

    def event_loop(self, handler: Callable, timeout: float = 30) -> None:
        """Run the monitor event loop.

        Args:
            handler: Callback function for each received frame
            timeout: Maximum time to run in seconds
        """
        if not self.sock_mon:
            self.start_monitor()

        deadline = time.time() + timeout
        while time.time() < deadline and not self.terminated:
            readable, _, _ = select.select([self.sock_mon], [], [], 0.5)
            if self.sock_mon in readable:
                frame = self.sock_mon.recv()
                if frame is not None:
                    handler(frame)

    def stop(self) -> None:
        """Stop monitor mode and clean up."""
        if self.sock_mon:
            self.sock_mon.close()
            self.sock_mon = None
        super().stop()
