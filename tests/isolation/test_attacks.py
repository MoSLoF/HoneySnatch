"""Tests for isolation attack result factories."""
from flyinghoneysnitch.isolation.attacks.base import AttackType, AttackOutcome
from flyinghoneysnitch.isolation.attacks.gtk_abuse import check_gtk_shared
from flyinghoneysnitch.isolation.attacks.broadcast_reflection import create_broadcast_reflection_result
from flyinghoneysnitch.isolation.attacks.gateway_bounce import create_gateway_bounce_result
from flyinghoneysnitch.isolation.attacks.port_steal import create_port_steal_result
from flyinghoneysnitch.isolation.attacks.client2client import create_c2c_result
from flyinghoneysnitch.isolation.attacks.client2monitor import create_c2m_result


def test_gtk_shared_vulnerable():
    gtk = b"\x01" * 16
    result = check_gtk_shared(gtk, gtk, 1, 1)
    assert result.outcome == AttackOutcome.VULNERABLE
    assert result.attack_type == AttackType.GTK_SHARED


def test_gtk_not_shared():
    result = check_gtk_shared(b"\x01" * 16, b"\x02" * 16, 1, 1)
    assert result.outcome == AttackOutcome.SECURE


def test_broadcast_reflection_vulnerable():
    result = create_broadcast_reflection_result(True)
    assert result.outcome == AttackOutcome.VULNERABLE
    assert result.attack_type == AttackType.BROADCAST_REFLECTION


def test_broadcast_reflection_secure():
    result = create_broadcast_reflection_result(False)
    assert result.outcome == AttackOutcome.SECURE


def test_gateway_bounce_vulnerable():
    result = create_gateway_bounce_result(True, "test details")
    assert result.outcome == AttackOutcome.VULNERABLE
    assert result.details == "test details"


def test_port_steal_downlink():
    result = create_port_steal_result("downlink", True)
    assert result.attack_type == AttackType.PORT_STEAL_DOWNLINK
    assert result.outcome == AttackOutcome.VULNERABLE


def test_port_steal_uplink():
    result = create_port_steal_result("uplink", False)
    assert result.attack_type == AttackType.PORT_STEAL_UPLINK
    assert result.outcome == AttackOutcome.SECURE


def test_c2c_result():
    result = create_c2c_result("arp", True, victim_mac="aa:bb:cc:dd:ee:ff")
    assert result.attack_type == AttackType.CLIENT_TO_CLIENT_ARP
    assert result.outcome == AttackOutcome.VULNERABLE
    assert result.victim_mac == "aa:bb:cc:dd:ee:ff"


def test_c2m_result():
    result = create_c2m_result(False, mode="ip")
    assert result.attack_type == AttackType.CLIENT_TO_MONITOR_IP
    assert result.outcome == AttackOutcome.SECURE
