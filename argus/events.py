"""Deterministic transformations from evidence to security events."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from argus.models import Evidence, SecurityEvent, Severity

_CROWDSEC_LATEST = "crowdsec.alert.latest"
_CROWDSEC_LATEST_REASON = "crowdsec.alert.latest_reason"
_CROWDSEC_LATEST_TIMESTAMP = "crowdsec.alert.latest_timestamp"
_CROWDSEC_RAW = "crowdsec.alert.raw"
_CROWDSEC_TIMESTAMP_FIELDS = ("created_at", "start_at", "stop_at", "updated_at")
_CROWDSEC_SUMMARY_FIELDS = ("message", "reason", "scenario")


def crowdsec_events_from_evidence(
    evidence: Iterable[Evidence],
) -> list[SecurityEvent]:
    """Interpret atomic CrowdSec alert evidence as security events."""
    events: list[SecurityEvent] = []

    for record in evidence:
        if record.source != _CROWDSEC_RAW:
            continue

        alert = _parse_raw_alert(record.content)
        if alert is None:
            continue

        timestamp = _raw_alert_timestamp(alert)
        if (
            timestamp is None
            and record.observed_at is not None
            and _is_aware(record.observed_at)
        ):
            timestamp = record.observed_at
        if timestamp is None:
            continue

        events.append(
            SecurityEvent(
                timestamp=timestamp,
                source="crowdsec",
                category="intrusion",
                severity=Severity.MEDIUM,
                summary=_raw_alert_summary(alert),
                evidence=(record,),
            )
        )

    return events


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


def _parse_raw_alert(content: str) -> dict[str, Any] | None:
    try:
        alert = json.loads(content)
    except json.JSONDecodeError:
        return None
    return alert if isinstance(alert, dict) else None


def _raw_alert_summary(alert: dict[str, Any]) -> str:
    for field in _CROWDSEC_SUMMARY_FIELDS:
        value = alert.get(field)
        if isinstance(value, str) and value.strip():
            return value
    return "CrowdSec alert"


def _raw_alert_timestamp(alert: dict[str, Any]) -> datetime | None:
    for field in _CROWDSEC_TIMESTAMP_FIELDS:
        timestamp = _parse_aware_datetime(alert.get(field))
        if timestamp is not None:
            return timestamp
    return None


def _parse_aware_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
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
