"""Pure, deterministic aggregation of attributed historical events."""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from argus.models import CollectionRun, SecurityEvent, Severity, TimestampBasis

REPEATED_FAILURE_THRESHOLD = 3
FAILURE_SUCCESS_WINDOW = timedelta(minutes=15)
MAX_TOP_IPS = 5
MAX_CROWDSEC_HIGHLIGHTS = 5


@dataclass(frozen=True)
class EventReference:
    collection_id: int
    identity: str | None
    timestamp: datetime
    timestamp_basis: TimestampBasis


@dataclass(frozen=True)
class IpActivity:
    address: str
    ssh_events: int
    crowdsec_alerts: int


@dataclass(frozen=True)
class RepeatedFailures:
    address: str
    count: int
    first: EventReference
    last: EventReference


@dataclass(frozen=True)
class FailureThenSuccess:
    address: str
    failure: EventReference
    success: EventReference


@dataclass(frozen=True)
class CrowdSecDetection:
    summary: str
    severity: Severity
    scenario: str | None
    source: str | None
    reference: EventReference


@dataclass(frozen=True)
class SecuritySummary:
    window_start: datetime | None
    window_end: datetime
    collection_count: int
    all_collection_count: int
    earliest_collection: datetime | None
    latest_collection: datetime | None
    total_events: int
    source_timestamp_count: int
    observed_timestamp_count: int
    ssh_successes: int
    ssh_failures: int
    ssh_invalid_users: int
    crowdsec_alerts: int
    unclassified_events: int
    severity_counts: tuple[tuple[Severity, int], ...]
    top_ips: tuple[IpActivity, ...]
    repeated_failures: tuple[RepeatedFailures, ...]
    failure_then_success: tuple[FailureThenSuccess, ...]
    crowdsec_detections: tuple[CrowdSecDetection, ...]


def build_security_summary(
    events: Iterable[tuple[SecurityEvent, int]],
    collections: Iterable[CollectionRun],
    *,
    window_start: datetime | None,
    window_end: datetime,
    all_collection_count: int | None = None,
) -> SecuritySummary:
    """Summarize all selected events without treating detections as incidents."""
    records = tuple(events)
    runs = tuple(collections)
    event_types = Counter()
    severities = Counter(event.severity for event, _ in records)
    ip_counts: dict[str, Counter[str]] = defaultdict(Counter)
    failures_by_ip: dict[str, list[EventReference]] = defaultdict(list)
    successes_by_ip: dict[str, list[EventReference]] = defaultdict(list)
    detections: list[CrowdSecDetection] = []
    for event, collection_id in records:
        details = dict(event.details)
        event_type = details.get("event_type") if event.source == "linux-auth" else None
        if event.source == "crowdsec":
            event_types["crowdsec"] += 1
        elif event_type in ("ssh_login_success", "ssh_login_failure", "ssh_invalid_user"):
            event_types[event_type] += 1
        else:
            event_types["unclassified"] += 1

        reference = EventReference(
            collection_id, event.identity, event.timestamp, event.timestamp_basis
        )
        address = _source_ip(event, details)
        if address is not None:
            ip_counts[address]["crowdsec" if event.source == "crowdsec" else "ssh"] += 1
            if event_type == "ssh_login_failure":
                failures_by_ip[address].append(reference)
            elif event_type == "ssh_login_success":
                successes_by_ip[address].append(reference)
        if event.source == "crowdsec":
            scope, value = details.get("source_scope"), details.get("source_value")
            source = " ".join(part for part in (scope, value) if part) or None
            detections.append(
                CrowdSecDetection(
                    event.summary, event.severity, details.get("scenario"), source,
                    reference,
                )
            )

    top_ips = tuple(
        IpActivity(address, counts["ssh"], counts["crowdsec"])
        for address, counts in sorted(
            ip_counts.items(),
            key=lambda item: (-(item[1]["ssh"] + item[1]["crowdsec"]), item[0]),
        )[:MAX_TOP_IPS]
    )
    repeated_findings: list[RepeatedFailures] = []
    for address, group in failures_by_ip.items():
        failures = sorted(group, key=lambda ref: ref.timestamp)
        if len(failures) >= REPEATED_FAILURE_THRESHOLD:
            repeated_findings.append(
                RepeatedFailures(address, len(failures), failures[0], failures[-1])
            )
    repeated = tuple(
        sorted(repeated_findings, key=lambda finding: (-finding.count, finding.address))
    )

    transitions: list[FailureThenSuccess] = []
    for address, successes in successes_by_ip.items():
        known_failures = sorted(
            (ref for ref in failures_by_ip[address] if ref.timestamp_basis is TimestampBasis.SOURCE),
            key=lambda ref: ref.timestamp,
        )
        for success in successes:
            if success.timestamp_basis is not TimestampBasis.SOURCE:
                continue
            prior = next(
                (
                    failure for failure in reversed(known_failures)
                    if timedelta(0) < success.timestamp - failure.timestamp <= FAILURE_SUCCESS_WINDOW
                ),
                None,
            )
            if prior is not None:
                transitions.append(FailureThenSuccess(address, prior, success))
    transitions.sort(key=lambda finding: finding.address)
    transitions.sort(key=lambda finding: finding.success.timestamp, reverse=True)
    detections.sort(key=lambda finding: finding.reference.timestamp, reverse=True)
    collection_times = tuple(run.collected_at for run in runs)
    return SecuritySummary(
        window_start=window_start,
        window_end=window_end,
        collection_count=len(runs),
        all_collection_count=(len(runs) if all_collection_count is None else all_collection_count),
        earliest_collection=min(collection_times) if collection_times else None,
        latest_collection=max(collection_times) if collection_times else None,
        total_events=len(records),
        source_timestamp_count=sum(event.timestamp_basis is TimestampBasis.SOURCE for event, _ in records),
        observed_timestamp_count=sum(event.timestamp_basis is TimestampBasis.OBSERVED for event, _ in records),
        ssh_successes=event_types["ssh_login_success"],
        ssh_failures=event_types["ssh_login_failure"],
        ssh_invalid_users=event_types["ssh_invalid_user"],
        crowdsec_alerts=event_types["crowdsec"],
        unclassified_events=event_types["unclassified"],
        severity_counts=tuple((severity, severities[severity]) for severity in Severity),
        top_ips=top_ips,
        repeated_failures=repeated,
        failure_then_success=tuple(transitions),
        crowdsec_detections=tuple(detections[:MAX_CROWDSEC_HIGHLIGHTS]),
    )


def _source_ip(event: SecurityEvent, details: dict[str, str]) -> str | None:
    if event.source == "linux-auth":
        value = details.get("remote_ip")
    elif event.source == "crowdsec" and details.get("source_scope", "ip").lower() == "ip":
        value = details.get("source_value")
    else:
        return None
    try:
        return str(ipaddress.ip_address(value)) if value is not None else None
    except ValueError:
        return None
