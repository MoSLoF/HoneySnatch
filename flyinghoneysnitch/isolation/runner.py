"""High-level test runner for client isolation testing.

Orchestrates attack setup, execution, and result collection.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from flyinghoneysnitch.isolation.attacks.base import AttackResult, AttackType, AttackOutcome
from flyinghoneysnitch.isolation.models import IsolationTestSession
from flyinghoneysnitch.isolation.config import IsolationConfig, find_hostap_binary, find_default_config


class IsolationTestRunner:
    """Run isolation tests and collect results.

    This is the high-level orchestrator that replaces airsnitch.py's main().
    It manages test sessions, coordinates attack execution, and collects results.
    """

    def __init__(self, interface: str, config_file: str = "",
                 config: Optional[IsolationConfig] = None, **kwargs):
        self.interface = interface
        self.config_file = config_file or (config.wpa_supplicant_config if config else "")
        self.config = config or IsolationConfig()
        self.options = kwargs
        self.session: Optional[IsolationTestSession] = None

    def _create_session(self, name: str = "") -> IsolationTestSession:
        """Create a new test session."""
        session = IsolationTestSession(
            session_id=str(uuid.uuid4())[:8],
            name=name or f"isolation-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            interface=self.interface,
            config_file=self.config_file,
            second_interface=self.options.get("second_interface", ""),
        )
        self.session = session
        return session

    def run_gtk_check(self, second_interface: str, **kwargs) -> AttackResult:
        """Check if GTK is shared between clients.

        Requires two wireless interfaces connected to the same network.
        """
        from flyinghoneysnitch.isolation.attacks.gtk_abuse import check_gtk_shared

        # Placeholder: actual implementation requires connecting both interfaces
        # and extracting GTK via wpaspy GET_GTK command
        return AttackResult(
            attack_type=AttackType.GTK_SHARED,
            outcome=AttackOutcome.INCONCLUSIVE,
            details="GTK check requires active wireless interfaces with hostap binaries",
        )

    def run_client2client(self, second_interface: str, mode: str = "ip",
                          **kwargs) -> AttackResult:
        """Run client-to-client isolation test.

        Args:
            second_interface: Second wireless interface for attacker
            mode: Attack mode - "arp", "ethernet", "ip", "broadcast"
        """
        from flyinghoneysnitch.isolation.attacks.client2client import create_c2c_result

        # Placeholder: full implementation requires hostap binaries running
        return AttackResult(
            attack_type=AttackType.CLIENT_TO_CLIENT_IP,
            outcome=AttackOutcome.INCONCLUSIVE,
            details=f"C2C {mode} test requires active wireless interfaces with hostap binaries",
        )

    def run_client2monitor(self, monitor_interface: str, **kwargs) -> AttackResult:
        """Run client-to-monitor isolation test."""
        from flyinghoneysnitch.isolation.attacks.client2monitor import create_c2m_result

        return AttackResult(
            attack_type=AttackType.CLIENT_TO_MONITOR,
            outcome=AttackOutcome.INCONCLUSIVE,
            details="C2M test requires active wireless interfaces with hostap binaries",
        )

    def run_port_steal(self, second_interface: str, direction: str = "downlink",
                       **kwargs) -> AttackResult:
        """Run port stealing attack test."""
        from flyinghoneysnitch.isolation.attacks.port_steal import create_port_steal_result

        return AttackResult(
            attack_type=(AttackType.PORT_STEAL_DOWNLINK if direction == "downlink"
                        else AttackType.PORT_STEAL_UPLINK),
            outcome=AttackOutcome.INCONCLUSIVE,
            details=f"Port steal ({direction}) requires active wireless interfaces",
        )

    def run_all(self, second_interface: str) -> IsolationTestSession:
        """Run all applicable isolation tests and return the session."""
        session = self._create_session("full-isolation-test")
        session.second_interface = second_interface

        # Run each test and collect results
        session.add_result(self.run_gtk_check(second_interface))
        session.add_result(self.run_client2client(second_interface, mode="ip"))
        session.add_result(self.run_client2client(second_interface, mode="arp"))
        session.add_result(self.run_client2client(second_interface, mode="broadcast"))
        session.add_result(self.run_port_steal(second_interface, direction="downlink"))
        session.add_result(self.run_port_steal(second_interface, direction="uplink"))

        session.finish()
        return session
