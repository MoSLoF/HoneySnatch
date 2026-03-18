"""Channel utilization chart widget showing AP distribution across WiFi channels."""

from __future__ import annotations

from collections import Counter

from honeysnatch.utils.logger import get_logger

log = get_logger("gui.channel_chart")

try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
    from matplotlib.figure import Figure

    class ChannelChart(FigureCanvasQTAgg):
        """Bar chart showing the number of APs per WiFi channel.

        Helps identify congested channels and plan optimal channel assignments.
        """

        def __init__(self, parent=None, width=8, height=3) -> None:
            self.fig = Figure(figsize=(width, height), facecolor="#1a1a2e")
            super().__init__(self.fig)

            self.ax = self.fig.add_subplot(111)
            self._setup_axes()
            self._channel_counts: Counter = Counter()

        def _setup_axes(self) -> None:
            self.ax.set_facecolor("#16213e")
            self.ax.set_ylabel("AP Count", color="#aaa")
            self.ax.set_xlabel("Channel", color="#aaa")
            self.ax.tick_params(colors="#aaa")
            self.ax.grid(True, alpha=0.2, color="#555", axis="y")
            for spine in self.ax.spines.values():
                spine.set_color("#333")

        def update_data(self, channel_counts: dict[int, int]) -> None:
            """Update with new channel count data.

            Args:
                channel_counts: Dict of channel_number -> AP count.
            """
            self._channel_counts = Counter(channel_counts)
            self._redraw()

        def add_ap_channel(self, channel: int) -> None:
            """Increment the count for a channel."""
            self._channel_counts[channel] += 1

        def refresh(self) -> None:
            """Redraw the chart."""
            self._redraw()

        def _redraw(self) -> None:
            self.ax.clear()
            self._setup_axes()

            if not self._channel_counts:
                self.draw_idle()
                return

            channels = sorted(self._channel_counts.keys())
            counts = [self._channel_counts[ch] for ch in channels]

            # Color 2.4 GHz vs 5 GHz differently
            colors = []
            for ch in channels:
                if ch <= 14:
                    colors.append("#e94560")  # 2.4 GHz = red
                elif ch <= 177:
                    colors.append("#0f3460")  # 5 GHz = blue
                else:
                    colors.append("#00ff88")  # 6 GHz = green

            bars = self.ax.bar(
                [str(ch) for ch in channels],
                counts,
                color=colors,
                edgecolor="#555",
                alpha=0.8,
            )

            # Add count labels on top of bars
            for bar, count in zip(bars, counts):
                if count > 0:
                    self.ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.1,
                        str(count),
                        ha="center", va="bottom",
                        color="#aaa", fontsize=8,
                    )

            self.ax.set_title("Channel Utilization", color="#aaa", fontsize=10)
            self.fig.tight_layout()
            self.draw_idle()

        def clear(self) -> None:
            """Clear all data."""
            self._channel_counts.clear()
            self._redraw()

except ImportError:
    from PyQt6.QtWidgets import QLabel

    class ChannelChart(QLabel):
        def __init__(self, parent=None, **kwargs):
            super().__init__("Channel chart requires matplotlib", parent)

        def update_data(self, *args, **kwargs): pass
        def add_ap_channel(self, *args, **kwargs): pass
        def refresh(self): pass
        def clear(self): pass
