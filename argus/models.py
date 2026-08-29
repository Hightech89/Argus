"""Core data models for Argus."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Evidence:
    """A single piece of evidence observed from a source."""

    source: str
    content: str
    observed_at: datetime | None = None
