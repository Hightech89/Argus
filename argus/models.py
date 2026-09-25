"""Core data models for Argus."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


@dataclass(frozen=True)
class Evidence:
    """A single piece of evidence observed from a source."""

    source: str
    content: str
    observed_at: datetime | None = None


class Severity(StrEnum):
    """Initial severity levels for interpreted security events."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SecurityEvent:
    """An interpreted event backed by one or more evidence records."""

    timestamp: datetime
    source: str
    category: str
    severity: Severity
    summary: str
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity value")
        if not isinstance(self.evidence, tuple):
            raise TypeError("evidence must be a tuple of Evidence records")
        if not self.evidence:
            raise ValueError("evidence must contain at least one Evidence record")
        if any(not isinstance(record, Evidence) for record in self.evidence):
            raise TypeError("evidence must contain only Evidence records")
