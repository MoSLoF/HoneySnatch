"""Client-to-client isolation attack implementations.

Tests whether two clients connected to the same AP (or different
APs on the same network) can communicate directly, bypassing
client isolation.

Refactored from AirSnitch's Client2Client class.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from flyinghoneysnitch.isolation.attacks.base import AttackResult, AttackType, AttackOutcome


@dataclass
class C2CTestConfig:
    """Configuration for a client-to-client test."""
    interface: str
    second_interface: str
    config_file: str = ""
    same_bss: bool = False
    other_bss: bool = False
    server: str = "8.8.8.8"
    port: int = 443
    no_ssid_check: bool = True
    timeout: int = 30


def create_c2c_result(mode: str, success: bool, details: str = "",
                      victim_mac: str = "", attacker_mac: str = "",
                      target_bssid: str = "", target_ssid: str = "") -> AttackResult:
    """Create a result for a client-to-client test.

    Args:
        mode: One of "arp", "ethernet", "ip", "broadcast"
        success: True if client-to-client communication succeeded (vulnerable)
        details: Additional details
    """
    type_map = {
        "arp": AttackType.CLIENT_TO_CLIENT_ARP,
        "ethernet": AttackType.CLIENT_TO_CLIENT_ETH,
        "ip": AttackType.CLIENT_TO_CLIENT_IP,
        "broadcast": AttackType.CLIENT_TO_CLIENT_BROADCAST,
    }
    attack_type = type_map.get(mode, AttackType.CLIENT_TO_CLIENT_IP)
    return AttackResult(
        attack_type=attack_type,
        outcome=AttackOutcome.VULNERABLE if success else AttackOutcome.SECURE,
        details=details,
        victim_mac=victim_mac,
        attacker_mac=attacker_mac,
        target_bssid=target_bssid,
        target_ssid=target_ssid,
    )
