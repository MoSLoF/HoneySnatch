"""Port stealing attack implementations.

Manipulates internal switches/bridges to intercept victim traffic
by spoofing gateway or victim MAC addresses. Supports both uplink
and downlink port stealing.
"""
from __future__ import annotations

from flyinghoneysnitch.isolation.attacks.base import AttackResult, AttackType, AttackOutcome


def create_port_steal_result(direction: str, intercepted: bool,
                             details: str = "") -> AttackResult:
    """Create a result for a port stealing test.

    Args:
        direction: "downlink" or "uplink"
        intercepted: True if traffic was successfully intercepted
        details: Additional details about the test
    """
    attack_type = (AttackType.PORT_STEAL_DOWNLINK if direction == "downlink"
                   else AttackType.PORT_STEAL_UPLINK)
    return AttackResult(
        attack_type=attack_type,
        outcome=AttackOutcome.VULNERABLE if intercepted else AttackOutcome.SECURE,
        details=details or (f"{direction.title()} traffic intercepted via port stealing"
                           if intercepted else f"{direction.title()} port stealing blocked"),
    )
