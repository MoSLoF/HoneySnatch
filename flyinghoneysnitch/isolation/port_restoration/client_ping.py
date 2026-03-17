"""Client-side port restoration ping utility.

Sends periodic frames to maintain port stealing state
after network reconnections.
"""
from __future__ import annotations


def start_client_ping(interface: str, target_mac: str, interval: float = 2.0) -> None:
    """Start sending periodic frames to maintain port steal.

    Args:
        interface: Network interface to send from
        target_mac: MAC address to spoof/target
        interval: Seconds between pings
    """
    # Placeholder for the full implementation from AirSnitch
    raise NotImplementedError(
        "Port restoration requires active wireless interfaces. "
        "See vendor/hostap_research/server_triggered_port_restoration/ "
        "for the original implementation."
    )
