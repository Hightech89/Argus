"""Deterministic transformations from evidence to security events."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from argus.models import Evidence, SecurityEvent, Severity

_CROWDSEC_LATEST = "crowdsec.alert.latest"
_CROWDSEC_LATEST_REASON = "crowdsec.alert.latest_reason"
_CROWDSEC_LATEST_TIMESTAMP = "crowdsec.alert.latest_timestamp"


def crowdsec_event_from_evidence(
    evidence: Iterable[Evidence],
) -> SecurityEvent | None:
    """Interpret the latest CrowdSec alert evidence as a security event."""
    records = list(evidence)
    latest = _first_record(records, _CROWDSEC_LATEST)
    if latest is None:
        return None

    reason = _first_record(records, _CROWDSEC_LATEST_REASON)
    native_timestamp = _first_record(records, _CROWDSEC_LATEST_TIMESTAMP)
    supporting_evidence = tuple(
        record for record in (latest, reason, native_timestamp) if record is not None
    )

    timestamp = None
    if native_timestamp is not None:
        timestamp = _parse_aware_datetime(native_timestamp.content)
    if timestamp is None:
        timestamp = _first_aware_observation(supporting_evidence)
    if timestamp is None:
        return None

    summary = reason.content if reason is not None and reason.content else latest.content
    return SecurityEvent(
        timestamp=timestamp,
        source="crowdsec",
        category="intrusion",
        severity=Severity.MEDIUM,
        summary=summary,
        evidence=supporting_evidence,
    )


def _first_record(records: list[Evidence], source: str) -> Evidence | None:
    return next((record for record in records if record.source == source), None)


def _parse_aware_datetime(value: str) -> datetime | None:
    try:
        timestamp = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return timestamp if _is_aware(timestamp) else None


def _first_aware_observation(evidence: tuple[Evidence, ...]) -> datetime | None:
    for record in evidence:
        if record.observed_at is not None and _is_aware(record.observed_at):
            return record.observed_at
    return None


def _is_aware(timestamp: datetime) -> bool:
    return timestamp.tzinfo is not None and timestamp.utcoffset() is not None
