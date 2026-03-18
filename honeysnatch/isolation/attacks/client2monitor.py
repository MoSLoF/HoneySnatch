"""Client-to-monitor isolation attack implementations.

Tests whether traffic from a connected client leaks to a
monitor-mode interface, indicating a failure in client isolation
at the radio level.

Refactored from AirSnitch's Client2Monitor class.
"""
from __future__ import annotations

from honeysnatch.isolation.attacks.base import AttackResult, AttackType, AttackOutcome


def create_c2m_result(leaked: bool, mode: str = "default",
                      details: str = "") -> AttackResult:
    """Create a result for a client-to-monitor test.

    Args:
        leaked: True if traffic leaked to monitor interface
        mode: "default" or "ip"
        details: Additional details
    """
    attack_type = AttackType.CLIENT_TO_MONITOR_IP if mode == "ip" else AttackType.CLIENT_TO_MONITOR
    return AttackResult(
        attack_type=attack_type,
        outcome=AttackOutcome.VULNERABLE if leaked else AttackOutcome.SECURE,
        details=details or ("Traffic leaked to monitor interface" if leaked
                           else "No traffic leakage detected"),
    )
