"""Deterministic transformations from evidence to security events."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from argus.models import Evidence, SecurityEvent, Severity, TimestampBasis

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
        if timestamp is not None:
            timestamp_basis = TimestampBasis.SOURCE
        elif record.observed_at is not None and _is_aware(record.observed_at):
            timestamp = record.observed_at
            timestamp_basis = TimestampBasis.OBSERVED
        else:
            continue

        events.append(
            SecurityEvent(
                timestamp=timestamp,
                timestamp_basis=timestamp_basis,
                source="crowdsec",
                category="intrusion",
                severity=Severity.MEDIUM,
                summary=_raw_alert_summary(alert),
                evidence=(record,),
                details=_raw_alert_details(alert),
                identity=_raw_alert_identity(alert),
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
    if timestamp is not None:
        timestamp_basis = TimestampBasis.SOURCE
    else:
        timestamp = _first_aware_observation(supporting_evidence)
        if timestamp is None:
            return None
        timestamp_basis = TimestampBasis.OBSERVED

    summary = reason.content if reason is not None and reason.content else latest.content
    return SecurityEvent(
        timestamp=timestamp,
        timestamp_basis=timestamp_basis,
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


def _raw_alert_identity(alert: dict[str, Any]) -> str | None:
    """Use only an authoritative CrowdSec alert ID, never inferred sameness."""
    value = alert.get("id")
    if isinstance(value, str):
        alert_id = value.strip()
    elif isinstance(value, int) and not isinstance(value, bool):
        alert_id = str(value)
    elif isinstance(value, float) and math.isfinite(value):
        alert_id = str(int(value)) if value.is_integer() else str(value)
    else:
        return None
    return f"crowdsec:alert:{alert_id}" if alert_id else None


def _raw_alert_details(alert: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Extract CrowdSec context in a fixed, documented semantic order."""
    source = alert.get("source")
    source = source if isinstance(source, dict) else {}
    decision = _first_decision(alert.get("decisions"))

    candidates = (
        ("alert_id", (alert.get("id"),)),
        ("scenario", (alert.get("scenario"),)),
        (
            "source_scope",
            (source.get("scope"), alert.get("source_scope"), alert.get("scope")),
        ),
        (
            "source_value",
            (
                source.get("value"),
                source.get("ip"),
                alert.get("source_value"),
                alert.get("source_ip"),
                alert.get("value"),
                alert.get("ip"),
            ),
        ),
        (
            "country",
            (
                source.get("cn"),
                source.get("country"),
                alert.get("country"),
                alert.get("cn"),
            ),
        ),
        ("as_number", (source.get("as_number"), alert.get("as_number"))),
        ("as_name", (source.get("as_name"), alert.get("as_name"))),
        ("event_count", (alert.get("events_count"), alert.get("event_count"))),
        (
            "machine",
            (
                alert.get("machine_id"),
                alert.get("machine_name"),
                alert.get("machine"),
            ),
        ),
        ("start_at", (alert.get("start_at"),)),
        ("stop_at", (alert.get("stop_at"),)),
        ("decision_type", (decision.get("type"),)),
        ("decision_scope", (decision.get("scope"),)),
        ("decision_value", (decision.get("value"),)),
        ("decision_duration", (decision.get("duration"),)),
    )

    details: list[tuple[str, str]] = []
    for key, values in candidates:
        value = _first_detail_value(values)
        if value is not None:
            details.append((key, value))
    return tuple(details)


def _first_decision(value: object) -> dict[str, Any]:
    if not isinstance(value, list):
        return {}
    return next((item for item in value if isinstance(item, dict)), {})


def _first_detail_value(values: tuple[object, ...]) -> str | None:
    for value in values:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
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
