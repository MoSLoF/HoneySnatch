"""Broadcast reflection attack implementation.

Tests whether broadcast frames sent by one client are reflected
back to other clients on the same or different BSS.
"""
from __future__ import annotations

from flyinghoneysnitch.isolation.attacks.base import AttackResult, AttackType, AttackOutcome


def create_broadcast_reflection_result(received: bool, details: str = "") -> AttackResult:
    """Create a result for a broadcast reflection test."""
    return AttackResult(
        attack_type=AttackType.BROADCAST_REFLECTION,
        outcome=AttackOutcome.VULNERABLE if received else AttackOutcome.SECURE,
        details=details or ("Broadcast frames reflected to other clients" if received
                           else "Broadcast frames not reflected"),
    )
