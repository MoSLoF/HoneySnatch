"""GTK (Group Temporal Key) abuse attack implementations.

Tests whether the GTK is shared between clients and whether
broadcast frames containing unicast IP packets can be injected
using the shared group key.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from honeysnatch.isolation.attacks.base import AttackResult, AttackType, AttackOutcome

if TYPE_CHECKING:
    from honeysnatch.isolation.runner import IsolationTestRunner


def check_gtk_shared(victim_gtk: bytes, attacker_gtk: bytes,
                     victim_gtk_idx: int, attacker_gtk_idx: int) -> AttackResult:
    """Check if two clients share the same GTK.

    If the GTK is shared, an attacker can inject broadcast frames
    that contain unicast IP packets directed at the victim.
    """
    shared = (victim_gtk == attacker_gtk and victim_gtk_idx == attacker_gtk_idx)
    return AttackResult(
        attack_type=AttackType.GTK_SHARED,
        outcome=AttackOutcome.VULNERABLE if shared else AttackOutcome.SECURE,
        details=f"GTK shared={shared}, victim_idx={victim_gtk_idx}, attacker_idx={attacker_gtk_idx}",
    )
