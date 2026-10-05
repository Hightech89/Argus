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


class TimestampBasis(StrEnum):
    """Origin of a security event's timestamp."""

    SOURCE = "source"
    OBSERVED = "observed"


@dataclass(frozen=True)
class SecurityEvent:
    """An interpreted event backed by one or more evidence records."""

    timestamp: datetime
    timestamp_basis: TimestampBasis
    source: str
    category: str
    severity: Severity
    summary: str
    evidence: tuple[Evidence, ...]
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        if not isinstance(self.timestamp_basis, TimestampBasis):
            raise TypeError("timestamp_basis must be a TimestampBasis value")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity value")
        if not isinstance(self.evidence, tuple):
            raise TypeError("evidence must be a tuple of Evidence records")
        if not self.evidence:
            raise ValueError("evidence must contain at least one Evidence record")
        if any(not isinstance(record, Evidence) for record in self.evidence):
            raise TypeError("evidence must contain only Evidence records")
        if not isinstance(self.details, tuple):
            raise TypeError("details must be a tuple of string pairs")
        for detail in self.details:
            if not isinstance(detail, tuple) or len(detail) != 2:
                raise TypeError("details must contain only key-value tuples")
            key, value = detail
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("detail keys and values must be strings")
