"""Policy compliance engine for SentryWeb.

Defines and enforces wireless security policies, such as
no-cellphone zones, authorized device lists, and encryption requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from flyinghoneysnitch.core.models import AccessPoint, Client, EncryptionType
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("policy")


class PolicyAction(Enum):
    """Action to take when a policy violation is detected."""

    ALERT = "alert"
    LOG = "log"
    BLOCK = "block"  # For future active response


@dataclass
class PolicyRule:
    """A single policy rule."""

    name: str
    description: str
    rule_type: str  # "require_encryption", "no_open", "authorized_only", "no_bluetooth", etc.
    action: PolicyAction = PolicyAction.ALERT
    severity: str = "warning"
    parameters: dict = field(default_factory=dict)
    enabled: bool = True


@dataclass
class PolicyViolation:
    """A detected policy violation."""

    rule: PolicyRule
    message: str
    device_id: str  # BSSID or MAC
    timestamp: datetime = field(default_factory=datetime.now)
    details: dict = field(default_factory=dict)


class PolicyEngine:
    """Enforces wireless security policies."""

    def __init__(self) -> None:
        self._rules: list[PolicyRule] = []
        self._violations: list[PolicyViolation] = []

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a policy rule."""
        self._rules.append(rule)
        log.info("Policy rule added: %s", rule.name)

    def add_default_rules(self) -> None:
        """Add sensible default security policy rules."""
        self._rules.extend([
            PolicyRule(
                name="No Open Networks",
                description="All access points must use encryption",
                rule_type="no_open",
                severity="critical",
            ),
            PolicyRule(
                name="No WEP",
                description="WEP encryption is prohibited (insecure)",
                rule_type="no_wep",
                severity="critical",
            ),
            PolicyRule(
                name="Require WPA2+",
                description="Minimum WPA2 encryption required",
                rule_type="require_min_encryption",
                parameters={"minimum": "WPA2"},
                severity="warning",
            ),
            PolicyRule(
                name="No WPS",
                description="WPS must be disabled (vulnerability)",
                rule_type="no_wps",
                severity="warning",
            ),
            PolicyRule(
                name="No Cellular Devices",
                description="Alert on any cellular device detection (no-cellphone zones)",
                rule_type="no_cellular",
                severity="warning",
                enabled=False,
            ),
            PolicyRule(
                name="Rogue Tower Detection",
                description="Alert on detected rogue base stations / IMSI catchers",
                rule_type="rogue_tower",
                severity="critical",
            ),
            PolicyRule(
                name="No 2G Towers",
                description="Alert on 2G-only towers (potential downgrade attack)",
                rule_type="no_2g",
                severity="warning",
            ),
        ])

    def check_ap(self, ap: AccessPoint) -> list[PolicyViolation]:
        """Check an access point against all enabled rules.

        Returns:
            List of violations found.
        """
        violations = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            violation = self._evaluate_ap_rule(rule, ap)
            if violation:
                violations.append(violation)
                self._violations.append(violation)

        return violations

    def check_client(self, client: Client) -> list[PolicyViolation]:
        """Check a client against applicable rules."""
        # Placeholder for future client-specific policies
        return []

    def get_violations(self) -> list[PolicyViolation]:
        """Get all recorded violations."""
        return self._violations.copy()

    def _evaluate_ap_rule(self, rule: PolicyRule, ap: AccessPoint) -> Optional[PolicyViolation]:
        """Evaluate a single rule against an AP."""
        if rule.rule_type == "no_open":
            if ap.encryption == EncryptionType.OPEN:
                return PolicyViolation(
                    rule=rule,
                    message=f"Open network: {ap.ssid or '[Hidden]'} ({ap.bssid})",
                    device_id=ap.bssid,
                )

        elif rule.rule_type == "no_wep":
            if ap.encryption == EncryptionType.WEP:
                return PolicyViolation(
                    rule=rule,
                    message=f"WEP network: {ap.ssid or '[Hidden]'} ({ap.bssid})",
                    device_id=ap.bssid,
                )

        elif rule.rule_type == "require_min_encryption":
            enc_order = {
                "Open": 0, "WEP": 1, "WPA": 2,
                "WPA2": 3, "WPA3": 4,
                "WPA2-Enterprise": 3, "WPA3-Enterprise": 4,
            }
            minimum = rule.parameters.get("minimum", "WPA2")
            min_level = enc_order.get(minimum, 3)
            ap_level = enc_order.get(ap.encryption.value, 0)

            if ap_level < min_level:
                return PolicyViolation(
                    rule=rule,
                    message=(
                        f"Encryption below minimum ({minimum}): "
                        f"{ap.ssid or '[Hidden]'} uses {ap.encryption.value}"
                    ),
                    device_id=ap.bssid,
                )

        elif rule.rule_type == "no_wps":
            if ap.wps:
                return PolicyViolation(
                    rule=rule,
                    message=f"WPS enabled: {ap.ssid or '[Hidden]'} ({ap.bssid})",
                    device_id=ap.bssid,
                )

        return None
