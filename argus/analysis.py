"""Deterministic analysis helpers for security events."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from argus.models import SecurityEvent, Severity, TimestampBasis


def deduplicate_events(events: Iterable[SecurityEvent]) -> tuple[SecurityEvent, ...]:
    """Keep the first event per identity and every event without an identity."""
    seen: set[str] = set()
    retained: list[SecurityEvent] = []
    for event in events:
        if event.identity is not None:
            if event.identity in seen:
                continue
            seen.add(event.identity)
        retained.append(event)
    return tuple(retained)


@dataclass(frozen=True)
class EventWindow:
    """Events selected by occurrence time and observation time."""

    occurred: tuple[SecurityEvent, ...]
    observed: tuple[SecurityEvent, ...]


@dataclass(frozen=True)
class DailySecurityBrief:
    """Structured daily security data ready for deterministic rendering."""

    window_start: datetime
    window_end: datetime
    occurred_count: int
    observed_count: int
    occurred: tuple[SecurityEvent, ...]
    observed: tuple[SecurityEvent, ...]
    occurred_severity_counts: tuple[tuple[Severity, int], ...]
    observed_severity_counts: tuple[tuple[Severity, int], ...]
    occurred_category_counts: tuple[tuple[str, int], ...]
    observed_category_counts: tuple[tuple[str, int], ...]


def build_daily_security_brief(
    event_window: EventWindow,
    *,
    window_start: datetime,
    window_end: datetime,
) -> DailySecurityBrief:
    """Aggregate an event window into immutable daily brief data."""
    _validate_aware_datetime(window_start, "window_start")
    _validate_aware_datetime(window_end, "window_end")
    if window_start > window_end:
        raise ValueError("window_start must not be after window_end")

    occurred = tuple(event_window.occurred)
    observed = tuple(event_window.observed)
    return DailySecurityBrief(
        window_start=window_start,
        window_end=window_end,
        occurred_count=len(occurred),
        observed_count=len(observed),
        occurred=occurred,
        observed=observed,
        occurred_severity_counts=_severity_counts(occurred),
        observed_severity_counts=_severity_counts(observed),
        occurred_category_counts=_category_counts(occurred),
        observed_category_counts=_category_counts(observed),
    )


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


def _severity_counts(
    events: tuple[SecurityEvent, ...],
) -> tuple[tuple[Severity, int], ...]:
    counts = {severity: 0 for severity in Severity}
    for event in events:
        counts[event.severity] += 1
    return tuple((severity, counts[severity]) for severity in Severity)


def _category_counts(
    events: tuple[SecurityEvent, ...],
) -> tuple[tuple[str, int], ...]:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.category] = counts.get(event.category, 0) + 1
    return tuple(sorted(counts.items()))


def _validate_aware_datetime(value: datetime, name: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
