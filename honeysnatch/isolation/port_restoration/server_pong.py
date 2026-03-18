"""Server-side port restoration pong utility.

Responds to client pings to trigger port restoration
on the network infrastructure.
"""
from __future__ import annotations


def start_server_pong(host: str = "0.0.0.0", port: int = 9999) -> None:
    """Start the server-side pong responder.

    Args:
        host: Address to bind to
        port: Port to listen on
    """
    raise NotImplementedError(
        "Port restoration server requires active network access. "
        "See vendor/hostap_research/server_triggered_port_restoration/ "
        "for the original implementation."
    )
