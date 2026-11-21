"""Core data models: Severity, Alert and ValidationResult.

An Alert refers to events only by ``event_id``; it holds no event rows and
knows nothing about pandas, so it stays small and easy to test.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Optional


class Severity(IntEnum):
    """Alert priority. IntEnum so alerts can be sorted by severity."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Alert:
    """A rule match. Worded as a pattern match, never as a confirmed compromise."""

    rule_id: str
    rule_name: str
    severity: Severity
    start_time: datetime
    end_time: datetime
    evidence_event_ids: tuple[int, ...]
    description: str
    thresholds: dict[str, Any] = field(default_factory=dict)  # settings that triggered it
    source_ip: Optional[str] = None
    user: Optional[str] = None
    alert_id: str = ""  # assigned by the engine after sorting, e.g. "A-001"

    @property
    def event_count(self) -> int:
        return len(self.evidence_event_ids)

    def to_dict(self) -> dict[str, Any]:
        """Plain, JSON-friendly form for the UI table and expected_alerts.json."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.label,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "event_count": self.event_count,
            "source_ip": self.source_ip,
            "user": self.user,
            "thresholds": dict(self.thresholds),
            "description": self.description,
            "evidence_event_ids": list(self.evidence_event_ids),
        }


@dataclass
class ValidationResult:
    """Returned by the validator so the UI can show every problem, not just the first."""

    errors: list[str] = field(default_factory=list)    # block analysis
    warnings: list[str] = field(default_factory=list)  # shown, but analysis continues

    @property
    def ok(self) -> bool:
        return not self.errors
