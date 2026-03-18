"""Configuration management for isolation testing.

Bridges between the wpa_supplicant .conf format used by AirSnitch
and the YAML-based configuration used by honeysnatch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class IsolationConfig:
    """Configuration for client isolation testing."""
    enabled: bool = False
    hostap_dir: str = ""
    wpa_supplicant_config: str = ""
    hostapd_config: str = ""
    default_server: str = "8.8.8.8"
    default_port: int = 443
    test_timeout: int = 30
    debug_level: int = 0


def find_hostap_binary(hostap_dir: str = "", ap: bool = False) -> Optional[str]:
    """Locate the hostapd or wpa_supplicant binary.

    Searches in order:
    1. Provided hostap_dir
    2. vendor/hostap_2_10/ relative to project root
    3. System PATH
    """
    binary_name = "hostapd" if ap else "wpa_supplicant"
    subdir = "hostapd" if ap else "wpa_supplicant"

    # Check provided directory
    if hostap_dir:
        candidate = Path(hostap_dir) / subdir / binary_name
        if candidate.exists():
            return str(candidate)

    # Check vendor directory relative to this file
    vendor_base = Path(__file__).resolve().parents[2] / "vendor" / "hostap_2_10"
    candidate = vendor_base / subdir / binary_name
    if candidate.exists():
        return str(candidate)

    # Fall back to vendor relative to project root (one more level up)
    vendor_base = Path(__file__).resolve().parents[3] / "vendor" / "hostap_2_10"
    candidate = vendor_base / subdir / binary_name
    if candidate.exists():
        return str(candidate)

    return None


def find_default_config(config_type: str = "supplicant") -> Optional[str]:
    """Locate the default configuration file in data/isolation/.

    Args:
        config_type: "supplicant" or "hostapd" or a specific filename
    """
    data_base = Path(__file__).resolve().parents[2] / "data" / "isolation"
    if not data_base.exists():
        data_base = Path(__file__).resolve().parents[3] / "data" / "isolation"

    if config_type == "supplicant":
        candidate = data_base / "client.conf"
    elif config_type == "hostapd":
        candidate = data_base / "hostapd.conf"
    else:
        candidate = data_base / config_type

    if candidate.exists():
        return str(candidate)
    return None
