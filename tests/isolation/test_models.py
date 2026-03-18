"""Tests for isolation data models."""
from honeysnatch.isolation.attacks.base import AttackResult, AttackType, AttackOutcome
from honeysnatch.isolation.models import IsolationTestSession


def test_attack_result_creation():
    result = AttackResult(
        attack_type=AttackType.CONTEXT_OVERRIDE,
        outcome=AttackOutcome.VULNERABLE,
        target_bssid="00:11:22:33:44:55",
        target_ssid="TestNetwork",
    )
    assert result.attack_type == AttackType.CONTEXT_OVERRIDE
    assert result.outcome == AttackOutcome.VULNERABLE
    assert result.target_bssid == "00:11:22:33:44:55"


def test_attack_result_defaults():
    result = AttackResult(
        attack_type=AttackType.GTK_SHARED,
        outcome=AttackOutcome.SECURE,
    )
    assert result.victim_mac == ""
    assert result.attacker_mac == ""
    assert result.details == ""
    assert result.duration_seconds == 0.0
    assert isinstance(result.raw_log, list)


def test_isolation_session_counts():
    session = IsolationTestSession(session_id="test1", name="Test")
    session.add_result(AttackResult(
        attack_type=AttackType.CONTEXT_OVERRIDE,
        outcome=AttackOutcome.VULNERABLE,
    ))
    session.add_result(AttackResult(
        attack_type=AttackType.CLIENT_TO_CLIENT_ARP,
        outcome=AttackOutcome.SECURE,
    ))
    session.add_result(AttackResult(
        attack_type=AttackType.GTK_SHARED,
        outcome=AttackOutcome.INCONCLUSIVE,
    ))
    assert session.vulnerable_count == 1
    assert session.secure_count == 1
    assert session.total_count == 3


def test_isolation_session_finish():
    session = IsolationTestSession(session_id="test2")
    assert session.end_time is None
    session.finish()
    assert session.end_time is not None


def test_attack_type_values():
    assert AttackType.CONTEXT_OVERRIDE.value == "context_override"
    assert AttackType.PORT_STEAL_DOWNLINK.value == "port_steal_downlink"
    assert AttackType.GATEWAY_BOUNCE.value == "gateway_bounce"


def test_attack_outcome_values():
    assert AttackOutcome.VULNERABLE.value == "vulnerable"
    assert AttackOutcome.SECURE.value == "secure"
    assert AttackOutcome.INCONCLUSIVE.value == "inconclusive"
    assert AttackOutcome.ERROR.value == "error"
