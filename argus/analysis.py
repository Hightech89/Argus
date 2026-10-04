"""Deterministic analysis helpers for security events."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from argus.models import SecurityEvent, TimestampBasis


@dataclass(frozen=True)
class EventWindow:
    """Events selected by occurrence time and observation time."""

    occurred: tuple[SecurityEvent, ...]
    observed: tuple[SecurityEvent, ...]


def select_event_window(
    events: Iterable[SecurityEvent],
    now: datetime,
    window: timedelta = timedelta(hours=24),
) -> EventWindow:
    """Select events within an inclusive rolling window by timestamp basis."""
    if not isinstance(now, datetime):
        raise TypeError("now must be a datetime")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if not isinstance(window, timedelta):
        raise TypeError("window must be a timedelta")
    if window <= timedelta(0):
        raise ValueError("window must be positive")

    cutoff = now - window
    occurred: list[SecurityEvent] = []
    observed: list[SecurityEvent] = []

    for event in events:
        if not cutoff <= event.timestamp <= now:
            continue
        if event.timestamp_basis is TimestampBasis.SOURCE:
            occurred.append(event)
        elif event.timestamp_basis is TimestampBasis.OBSERVED:
            observed.append(event)

    return EventWindow(occurred=tuple(occurred), observed=tuple(observed))
