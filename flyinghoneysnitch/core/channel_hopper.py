"""WiFi channel hopping for passive scanning.

Rotates through available WiFi channels at a configurable interval
to ensure all channels are monitored during a scan session.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from flyinghoneysnitch.utils.interfaces import set_channel
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("channel_hopper")

# Standard 2.4 GHz channels (1-14, region-dependent)
CHANNELS_2_4GHZ = list(range(1, 15))

# Standard 5 GHz channels (UNII-1 through UNII-3)
CHANNELS_5GHZ = [
    36, 40, 44, 48,        # UNII-1
    52, 56, 60, 64,        # UNII-2
    100, 104, 108, 112,    # UNII-2 Extended
    116, 120, 124, 128,
    132, 136, 140, 144,
    149, 153, 157, 161,    # UNII-3
    165,
]


class ChannelHopper:
    """Hops through WiFi channels on a monitor-mode interface.

    Runs in a background thread, cycling through the configured channel
    list at the specified interval.
    """

    def __init__(
        self,
        interface: str,
        channels: Optional[list[int]] = None,
        hop_interval: float = 0.5,
        on_channel_change: Optional[Callable[[int], None]] = None,
    ) -> None:
        """
        Args:
            interface: Monitor-mode wireless interface name.
            channels: List of channels to hop through. Defaults to 2.4 GHz channels.
            hop_interval: Seconds between channel hops.
            on_channel_change: Optional callback when channel changes.
        """
        self.interface = interface
        self.channels = channels or CHANNELS_2_4GHZ.copy()
        self.hop_interval = hop_interval
        self.on_channel_change = on_channel_change

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._current_channel = 0
        self._channel_index = 0
        self._lock = threading.Lock()

    @property
    def current_channel(self) -> int:
        """The channel currently being monitored."""
        return self._current_channel

    def start(self) -> None:
        """Start channel hopping in a background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._hop_loop,
            name="ChannelHopper",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "Channel hopper started on %s: %d channels, %.1fs interval",
            self.interface, len(self.channels), self.hop_interval,
        )

    def stop(self) -> None:
        """Stop channel hopping."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        log.info("Channel hopper stopped")

    def set_channels(self, channels: list[int]) -> None:
        """Update the channel list."""
        with self._lock:
            self.channels = channels
            self._channel_index = 0

    def pin_channel(self, channel: int) -> None:
        """Pin scanning to a single channel (stop hopping)."""
        with self._lock:
            self.channels = [channel]
            self._channel_index = 0
        log.info("Pinned to channel %d", channel)

    def _hop_loop(self) -> None:
        """Main hopping loop running in background thread."""
        while self._running:
            with self._lock:
                if not self.channels:
                    time.sleep(self.hop_interval)
                    continue

                channel = self.channels[self._channel_index % len(self.channels)]
                self._channel_index = (self._channel_index + 1) % len(self.channels)

            if set_channel(self.interface, channel):
                self._current_channel = channel
                if self.on_channel_change:
                    try:
                        self.on_channel_change(channel)
                    except Exception as e:
                        log.error("Channel change callback error: %s", e)

            time.sleep(self.hop_interval)
