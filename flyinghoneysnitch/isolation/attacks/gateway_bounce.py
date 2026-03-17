"""Gateway bouncing attack implementation.

Bypasses MAC/Ethernet layer client isolation by routing through
the gateway. Sends packets with attacker MAC at Ethernet layer
but victim IP at IP layer, causing the gateway to forward packets
to the victim.
"""
from __future__ import annotations

from flyinghoneysnitch.isolation.attacks.base import AttackResult, AttackType, AttackOutcome


def create_gateway_bounce_result(intercepted: bool, details: str = "") -> AttackResult:
    """Create a result for a gateway bouncing test."""
    return AttackResult(
        attack_type=AttackType.GATEWAY_BOUNCE,
        outcome=AttackOutcome.VULNERABLE if intercepted else AttackOutcome.SECURE,
        details=details or ("Gateway forwarded spoofed packets to victim" if intercepted
                           else "Gateway blocked spoofed packets"),
    )
