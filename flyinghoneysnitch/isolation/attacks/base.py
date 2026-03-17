"""Base classes and result models for isolation attacks."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class AttackType(Enum):
    """Types of client isolation attacks."""
    CONTEXT_OVERRIDE = "context_override"
    CLIENT_TO_CLIENT_ARP = "c2c_arp"
    CLIENT_TO_CLIENT_ETH = "c2c_ethernet"
    CLIENT_TO_CLIENT_IP = "c2c_ip"
    CLIENT_TO_CLIENT_BROADCAST = "c2c_broadcast"
    CLIENT_TO_MONITOR = "c2m"
    CLIENT_TO_MONITOR_IP = "c2m_ip"
    PORT_STEAL_DOWNLINK = "port_steal_downlink"
    PORT_STEAL_UPLINK = "port_steal_uplink"
    GTK_SHARED = "gtk_shared"
    GTK_INJECT = "gtk_inject"
    BROADCAST_REFLECTION = "broadcast_reflection"
    GATEWAY_BOUNCE = "gateway_bounce"


class AttackOutcome(Enum):
    """Result of an attack test."""
    VULNERABLE = "vulnerable"
    SECURE = "secure"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass
class AttackResult:
    """Result of a single attack test."""
    attack_type: AttackType
    outcome: AttackOutcome
    target_bssid: str = ""
    target_ssid: str = ""
    victim_identity: str = ""
    attacker_identity: str = ""
    victim_mac: str = ""
    attacker_mac: str = ""
    details: str = ""
    duration_seconds: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    raw_log: list[str] = field(default_factory=list)
