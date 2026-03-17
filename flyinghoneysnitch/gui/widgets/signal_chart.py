"""Real-time signal strength chart widget using matplotlib."""

from __future__ import annotations

from collections import deque
from typing import Optional

from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("gui.signal_chart")

try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
    from matplotlib.figure import Figure

    class SignalChart(FigureCanvasQTAgg):
        """Real-time RSSI chart embedded in PyQt6.

        Displays a rolling time-series of signal strength for
        selected access points.
        """

        MAX_POINTS = 120  # ~2 minutes at 1 Hz

        def __init__(self, parent=None, width=8, height=3) -> None:
            self.fig = Figure(figsize=(width, height), facecolor="#1a1a2e")
            super().__init__(self.fig)

            self.ax = self.fig.add_subplot(111)
            self._setup_axes()

            # Data: bssid -> deque of RSSI values
            self._series: dict[str, deque] = {}
            self._lines: dict[str, object] = {}
            self._colors = [
                "#e94560", "#0f3460", "#00ff88", "#ffaa00",
                "#ff6b6b", "#4ecdc4", "#45b7d1", "#96c93d",
            ]
            self._color_idx = 0

        def _setup_axes(self) -> None:
            self.ax.set_facecolor("#16213e")
            self.ax.set_ylabel("RSSI (dBm)", color="#aaa")
            self.ax.set_xlabel("Time (s)", color="#aaa")
            self.ax.set_ylim(-100, -20)
            self.ax.tick_params(colors="#aaa")
            self.ax.grid(True, alpha=0.2, color="#555")
            for spine in self.ax.spines.values():
                spine.set_color("#333")

        def add_ap(self, bssid: str, label: str = "") -> None:
            """Start tracking an AP's signal strength."""
            if bssid in self._series:
                return

            self._series[bssid] = deque(maxlen=self.MAX_POINTS)
            color = self._colors[self._color_idx % len(self._colors)]
            self._color_idx += 1

            line, = self.ax.plot([], [], color=color, linewidth=1.5,
                                label=label or bssid[:8])
            self._lines[bssid] = line
            self.ax.legend(loc="upper left", fontsize=7, facecolor="#16213e",
                          edgecolor="#333", labelcolor="#aaa")

        def remove_ap(self, bssid: str) -> None:
            """Stop tracking an AP."""
            if bssid in self._series:
                del self._series[bssid]
                line = self._lines.pop(bssid, None)
                if line:
                    line.remove()

        def update_signal(self, bssid: str, rssi: int) -> None:
            """Add a new RSSI value for an AP."""
            if bssid not in self._series:
                self.add_ap(bssid)

            self._series[bssid].append(rssi)

        def refresh(self) -> None:
            """Redraw the chart with current data."""
            for bssid, data in self._series.items():
                if bssid in self._lines and data:
                    x = list(range(len(data)))
                    self._lines[bssid].set_data(x, list(data))

            if self._series:
                max_len = max(len(d) for d in self._series.values())
                self.ax.set_xlim(0, max(max_len, 30))

            self.draw_idle()

        def clear(self) -> None:
            """Clear all data."""
            self._series.clear()
            for line in self._lines.values():
                line.remove()
            self._lines.clear()
            self._color_idx = 0
            self.draw_idle()

except ImportError:
    # Fallback if matplotlib is not available
    from PyQt6.QtWidgets import QLabel

    class SignalChart(QLabel):
        MAX_POINTS = 120

        def __init__(self, parent=None, **kwargs):
            super().__init__("Signal chart requires matplotlib", parent)

        def add_ap(self, *args, **kwargs): pass
        def remove_ap(self, *args, **kwargs): pass
        def update_signal(self, *args, **kwargs): pass
        def refresh(self): pass
        def clear(self): pass
