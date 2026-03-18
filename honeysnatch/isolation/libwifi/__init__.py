"""libwifi - Low-level Wi-Fi frame construction and monitor mode utilities.

Adapted from the AirSnitch/libwifi library.
Provides Scapy-based frame construction, monitor mode socket management,
DHCP/ARP helpers, and encryption utilities.
"""
try:
    from honeysnatch.isolation.libwifi.wifi import *  # noqa: F401,F403
except ImportError:
    pass  # scapy Linux/Unix dependencies not available on Windows
