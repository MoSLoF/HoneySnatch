"""Permission and capability checks for FlyingHoneySnitch.

Wireless scanning requires elevated privileges (root or CAP_NET_RAW).
This module checks and reports on available capabilities.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("permissions")


@dataclass
class PermissionStatus:
    """System permission status for wireless operations."""

    is_root: bool = False
    has_cap_net_raw: bool = False
    has_cap_net_admin: bool = False
    can_scan: bool = False
    message: str = ""


def check_permissions() -> PermissionStatus:
    """Check if the current process has sufficient permissions for scanning.

    Wireless scanning requires either:
    - Running as root (UID 0)
    - CAP_NET_RAW and CAP_NET_ADMIN capabilities

    Returns:
        PermissionStatus with details about available permissions.
    """
    status = PermissionStatus()

    status.is_root = os.geteuid() == 0

    if status.is_root:
        status.has_cap_net_raw = True
        status.has_cap_net_admin = True
        status.can_scan = True
        status.message = "Running as root - full permissions available"
        return status

    # Check Linux capabilities
    try:
        result = subprocess.run(
            ["capsh", "--print"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            caps = result.stdout.lower()
            status.has_cap_net_raw = "cap_net_raw" in caps
            status.has_cap_net_admin = "cap_net_admin" in caps
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log.debug("capsh not available, checking /proc")
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_hex = int(line.split(":")[1].strip(), 16)
                        status.has_cap_net_raw = bool(cap_hex & (1 << 13))
                        status.has_cap_net_admin = bool(cap_hex & (1 << 12))
        except (OSError, ValueError):
            pass

    status.can_scan = status.has_cap_net_raw and status.has_cap_net_admin

    if status.can_scan:
        status.message = "Required capabilities (CAP_NET_RAW, CAP_NET_ADMIN) available"
    else:
        missing = []
        if not status.has_cap_net_raw:
            missing.append("CAP_NET_RAW")
        if not status.has_cap_net_admin:
            missing.append("CAP_NET_ADMIN")
        status.message = (
            f"Missing capabilities: {', '.join(missing)}. "
            "Run as root or grant capabilities: "
            "sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
        )

    return status


def require_scan_permissions() -> None:
    """Raise an error if scanning permissions are not available."""
    status = check_permissions()
    if not status.can_scan:
        raise PermissionError(
            f"Insufficient permissions for wireless scanning. {status.message}"
        )
