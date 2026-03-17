"""WPA supplicant control for isolation testing.

Provides supplicant lifecycle management, DHCP/ARP/TCP operations,
and attack sequence coordination.

Refactored from AirSnitch's Supplicant and ClientInfo classes.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional

from flyinghoneysnitch.isolation.daemon import Daemon, IsolationDaemonError
from flyinghoneysnitch.isolation.libwifi.wifi import log, STATUS, DEBUG, ERROR, WARNING


@dataclass
class ClientInfo:
    """Information about a connected client."""
    mac: str = ""
    ip: str = ""
    bssid: str = ""
    ssid: str = ""
    key_mgmt: str = ""
    identity: str = ""
    gtk: bytes = b""
    gtk_idx: int = 0


class Supplicant(Daemon):
    """WPA supplicant wrapper for isolation testing.

    Manages client connection lifecycle including scanning, association,
    IP acquisition, and key extraction.
    """

    def __init__(self, iface: str, config_file: str = "",
                 hostap_dir: str = "", debug: int = 0):
        super().__init__(iface, config_file=config_file,
                         hostap_dir=hostap_dir, debug=debug,
                         ap_mode=False)
        self.client_info = ClientInfo()
        self.connected = False

    def start_and_connect(self) -> ClientInfo:
        """Start wpa_supplicant and connect to the configured network.

        Returns:
            ClientInfo with connection details
        """
        self.start()
        self._wait_for_connection()
        self._extract_keys()
        return self.client_info

    def _wait_for_connection(self, timeout: float = 30) -> None:
        """Wait for the supplicant to connect."""
        if self.wait_event("CTRL-EVENT-CONNECTED", timeout=timeout):
            self.connected = True
            self._update_status()
            log(STATUS, f"Connected to {self.client_info.ssid} "
                f"(BSSID: {self.client_info.bssid})")
        else:
            raise IsolationDaemonError(
                f"Failed to connect within {timeout}s. "
                "Check the configuration file and network availability."
            )

    def _update_status(self) -> None:
        """Update client info from wpa_supplicant status."""
        status = self.wpaspy_command("STATUS")
        if status is None:
            return

        for line in status.split("\n"):
            if "=" in line:
                key, value = line.split("=", 1)
                if key == "bssid":
                    self.client_info.bssid = value
                elif key == "ssid":
                    self.client_info.ssid = value
                elif key == "key_mgmt":
                    self.client_info.key_mgmt = value
                elif key == "ip_address":
                    self.client_info.ip = value

    def _extract_keys(self) -> None:
        """Extract encryption keys from wpa_supplicant."""
        try:
            gtk_response = self.wpaspy_command("GET_GTK")
            if gtk_response:
                parts = gtk_response.split()
                if len(parts) >= 2:
                    self.client_info.gtk = bytes.fromhex(parts[0])
                    self.client_info.gtk_idx = int(parts[1])
        except (IsolationDaemonError, ValueError) as e:
            log(WARNING, f"Could not extract GTK: {e}")

    def get_gtk(self) -> tuple[bytes, int]:
        """Get the current GTK and its index."""
        return self.client_info.gtk, self.client_info.gtk_idx

    def get_ip(self) -> str:
        """Get the client's IP address."""
        return self.client_info.ip

    def scan(self) -> str:
        """Trigger a scan and return results."""
        self.wpaspy_command("SCAN")
        self.wait_event("CTRL-EVENT-SCAN-RESULTS", timeout=10)
        return self.wpaspy_command("SCAN_RESULTS") or ""

    def disconnect(self) -> None:
        """Disconnect from the current network."""
        self.wpaspy_command("DISCONNECT", can_fail=True)
        self.connected = False

    def reconnect(self) -> None:
        """Reconnect to the network."""
        self.wpaspy_command("REASSOCIATE")
        self._wait_for_connection()
