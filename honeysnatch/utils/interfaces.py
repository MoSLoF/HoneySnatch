"""Network interface management for wireless scanning.

Handles detection of wireless interfaces, enabling/disabling monitor mode,
and querying interface capabilities.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Optional

from honeysnatch.utils.logger import get_logger

log = get_logger("interfaces")


@dataclass
class WirelessInterface:
    """A wireless network interface."""

    name: str
    phy: str = ""
    driver: str = ""
    chipset: str = ""
    mode: str = "managed"  # managed, monitor, master
    mac: str = ""
    supports_monitor: bool = False


def list_wireless_interfaces() -> list[WirelessInterface]:
    """List all wireless interfaces on the system.

    Uses `iw dev` and `/sys/class/net` to enumerate wireless interfaces.

    Returns:
        List of WirelessInterface objects.
    """
    interfaces = []

    try:
        result = subprocess.run(
            ["iw", "dev"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            log.warning("iw dev failed: %s", result.stderr)
            return interfaces

        current_phy = ""
        current_iface: Optional[dict] = None

        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("phy#"):
                current_phy = line.rstrip()
            elif line.startswith("Interface"):
                if current_iface:
                    interfaces.append(WirelessInterface(**current_iface))
                current_iface = {"name": line.split()[-1], "phy": current_phy}
            elif current_iface:
                if line.startswith("type"):
                    current_iface["mode"] = line.split()[-1]
                elif line.startswith("addr"):
                    current_iface["mac"] = line.split()[-1]

        if current_iface:
            interfaces.append(WirelessInterface(**current_iface))

        # Check monitor mode support for each interface
        for iface in interfaces:
            iface.supports_monitor = _check_monitor_support(iface.phy)
            iface.driver = _get_driver(iface.name)

    except FileNotFoundError:
        log.error("'iw' command not found. Install iw: sudo apt install iw")
    except subprocess.TimeoutExpired:
        log.error("Timed out enumerating wireless interfaces")

    return interfaces


def enable_monitor_mode(interface: str) -> Optional[str]:
    """Enable monitor mode on a wireless interface.

    Uses `ip link` and `iw` commands. May create a new monitor interface.

    Args:
        interface: Name of the wireless interface (e.g., wlan0).

    Returns:
        The name of the monitor-mode interface, or None on failure.
    """
    log.info("Enabling monitor mode on %s", interface)

    try:
        # Bring interface down
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            capture_output=True, text=True, timeout=10, check=True,
        )

        # Set monitor mode
        subprocess.run(
            ["iw", interface, "set", "monitor", "none"],
            capture_output=True, text=True, timeout=10, check=True,
        )

        # Bring interface back up
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            capture_output=True, text=True, timeout=10, check=True,
        )

        log.info("Monitor mode enabled on %s", interface)
        return interface

    except subprocess.CalledProcessError as e:
        log.error("Failed to enable monitor mode on %s: %s", interface, e.stderr)

        # Try creating a separate monitor interface
        mon_name = f"{interface}mon"
        try:
            subprocess.run(
                ["iw", interface, "interface", "add", mon_name, "type", "monitor"],
                capture_output=True, text=True, timeout=10, check=True,
            )
            subprocess.run(
                ["ip", "link", "set", mon_name, "up"],
                capture_output=True, text=True, timeout=10, check=True,
            )
            log.info("Created monitor interface %s", mon_name)
            return mon_name
        except subprocess.CalledProcessError as e2:
            log.error("Failed to create monitor interface: %s", e2.stderr)
            return None


def disable_monitor_mode(interface: str) -> bool:
    """Disable monitor mode and return to managed mode.

    Args:
        interface: Name of the monitor-mode interface.

    Returns:
        True if successful.
    """
    log.info("Disabling monitor mode on %s", interface)

    try:
        # If it's a virtual monitor interface (e.g., wlan0mon), remove it
        if interface.endswith("mon"):
            subprocess.run(
                ["iw", interface, "del"],
                capture_output=True, text=True, timeout=10, check=True,
            )
            log.info("Removed monitor interface %s", interface)
            return True

        # Otherwise, switch back to managed mode
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        subprocess.run(
            ["iw", interface, "set", "type", "managed"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        log.info("Managed mode restored on %s", interface)
        return True

    except subprocess.CalledProcessError as e:
        log.error("Failed to disable monitor mode: %s", e.stderr)
        return False


def set_channel(interface: str, channel: int) -> bool:
    """Set the wireless interface to a specific channel.

    Args:
        interface: Monitor-mode interface name.
        channel: WiFi channel number.

    Returns:
        True if successful.
    """
    try:
        subprocess.run(
            ["iw", interface, "set", "channel", str(channel)],
            capture_output=True, text=True, timeout=5, check=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        log.debug("Failed to set channel %d on %s: %s", channel, interface, e.stderr)
        return False


def _check_monitor_support(phy: str) -> bool:
    """Check if a physical device supports monitor mode."""
    try:
        result = subprocess.run(
            ["iw", phy, "info"],
            capture_output=True, text=True, timeout=10,
        )
        return "monitor" in result.stdout.lower()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _get_driver(interface: str) -> str:
    """Get the kernel driver for a network interface."""
    try:
        link = f"/sys/class/net/{interface}/device/driver"
        result = subprocess.run(
            ["readlink", "-f", link],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip().split("/")[-1]
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return ""
