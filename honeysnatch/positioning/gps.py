"""GPS integration via gpsd for outdoor positioning.

Connects to the gpsd daemon to receive GPS fixes and provide
position data to the scanner and mapping components.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Callable, Optional

from honeysnatch.core.models import GeoPosition
from honeysnatch.utils.logger import get_logger

log = get_logger("gps")


class GpsClient:
    """GPS client that connects to gpsd for position data.

    Runs in a background thread and provides the latest position
    fix to consumers via callback or polling.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2947,
        on_fix: Optional[Callable[[GeoPosition], None]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.on_fix = on_fix

        self._position: Optional[GeoPosition] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._has_fix = False

    @property
    def position(self) -> Optional[GeoPosition]:
        """The most recent GPS position."""
        with self._lock:
            return self._position

    @property
    def has_fix(self) -> bool:
        return self._has_fix

    def start(self) -> None:
        """Start receiving GPS data from gpsd."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._gps_loop,
            name="GpsClient",
            daemon=True,
        )
        self._thread.start()
        log.info("GPS client started (gpsd %s:%d)", self.host, self.port)

    def stop(self) -> None:
        """Stop the GPS client."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        log.info("GPS client stopped")

    def _gps_loop(self) -> None:
        """Background loop that reads from gpsd."""
        try:
            import gpsd

            gpsd.connect(host=self.host, port=self.port)
            log.info("Connected to gpsd")

            while self._running:
                try:
                    packet = gpsd.get_current()

                    if packet.mode >= 2:  # 2D or 3D fix
                        position = GeoPosition(
                            latitude=packet.lat,
                            longitude=packet.lon,
                            altitude=packet.alt if packet.mode >= 3 else None,
                            accuracy=getattr(packet, "error", {}).get("t", None),
                            source="gps",
                            timestamp=datetime.now(),
                        )

                        with self._lock:
                            self._position = position
                            self._has_fix = True

                        if self.on_fix:
                            try:
                                self.on_fix(position)
                            except Exception as e:
                                log.error("GPS fix callback error: %s", e)

                except Exception as e:
                    log.debug("GPS read error: %s", e)

                time.sleep(1)

        except ImportError:
            log.error("gpsd-py3 not installed. Install with: pip install gpsd-py3")
        except Exception as e:
            log.error("GPS connection failed: %s", e)
            self._running = False


class SimulatedGps:
    """Simulated GPS for testing without hardware.

    Generates a path of positions for development/testing.
    """

    def __init__(
        self,
        start_lat: float = 38.9072,
        start_lon: float = -77.0369,
        speed_m_per_s: float = 1.5,
    ) -> None:
        self._lat = start_lat
        self._lon = start_lon
        self._speed = speed_m_per_s
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._position: Optional[GeoPosition] = None
        self.on_fix: Optional[Callable[[GeoPosition], None]] = None

    @property
    def position(self) -> Optional[GeoPosition]:
        return self._position

    @property
    def has_fix(self) -> bool:
        return self._position is not None

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._sim_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _sim_loop(self) -> None:
        import math
        import random

        bearing = random.uniform(0, 360)

        while self._running:
            # Random walk
            bearing += random.uniform(-15, 15)
            bearing %= 360

            # Move
            d = self._speed / 111320.0  # degrees per second (approx)
            self._lat += d * math.cos(math.radians(bearing))
            self._lon += d * math.sin(math.radians(bearing)) / math.cos(math.radians(self._lat))

            self._position = GeoPosition(
                latitude=self._lat,
                longitude=self._lon,
                altitude=50.0,
                accuracy=5.0,
                source="simulated",
            )

            if self.on_fix:
                try:
                    self.on_fix(self._position)
                except Exception:
                    pass

            time.sleep(1)
