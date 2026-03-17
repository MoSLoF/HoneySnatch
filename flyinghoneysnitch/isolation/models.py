"""Data models for client isolation testing."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from flyinghoneysnitch.isolation.attacks.base import AttackResult, AttackOutcome


@dataclass
class IsolationTestSession:
    """A complete isolation testing session."""
    session_id: str
    name: str = ""
    interface: str = ""
    second_interface: str = ""
    target_ssid: str = ""
    target_bssid: str = ""
    config_file: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    results: list[AttackResult] = field(default_factory=list)
    notes: str = ""

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for r in self.results if r.outcome == AttackOutcome.VULNERABLE)

    @property
    def secure_count(self) -> int:
        return sum(1 for r in self.results if r.outcome == AttackOutcome.SECURE)

    @property
    def total_count(self) -> int:
        return len(self.results)

    def add_result(self, result: AttackResult) -> None:
        self.results.append(result)

    def finish(self) -> None:
        self.end_time = datetime.now()
