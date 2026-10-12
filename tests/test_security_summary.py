"""Pure historical security-summary aggregation tests."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from argus.models import CollectionRun, Evidence, SecurityEvent, Severity, TimestampBasis
from argus.security_summary import (
    FAILURE_SUCCESS_WINDOW,
    REPEATED_FAILURE_THRESHOLD,
    build_security_summary,
)

NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)


def event(
    source: str,
    timestamp: datetime,
    *,
    kind: str | None = None,
    ip: str | None = None,
    basis: TimestampBasis = TimestampBasis.SOURCE,
    identity: str | None = None,
    severity: Severity = Severity.LOW,
    details: tuple[tuple[str, str], ...] = (),
) -> SecurityEvent:
    fields = list(details)
    if kind is not None:
        fields.append(("event_type", kind))
    if ip is not None:
        fields.append(("remote_ip" if source == "linux-auth" else "source_value", ip))
    return SecurityEvent(
        timestamp=timestamp,
        timestamp_basis=basis,
        source=source,
        category="authentication" if source == "linux-auth" else "intrusion",
        severity=severity,
        summary="test event",
        evidence=(Evidence("test.raw", "{}", NOW),),
        details=tuple(fields),
        identity=identity,
    )


def build(records: list[tuple[SecurityEvent, int]], runs: tuple[CollectionRun, ...] = ()):
    return build_security_summary(records, runs, window_start=NOW - timedelta(hours=24), window_end=NOW)


class SecuritySummaryTests(unittest.TestCase):
    def test_authentication_crowdsec_severity_and_unclassified_counts(self) -> None:
        records = [
            (event("linux-auth", NOW, kind="ssh_login_success", ip="192.0.2.1", severity=Severity.INFO), 1),
            (event("linux-auth", NOW, kind="ssh_login_failure", ip="192.0.2.1"), 1),
            (event("linux-auth", NOW, kind="ssh_invalid_user", ip="192.0.2.2"), 1),
            (event("linux-auth", NOW, kind="unknown", severity=Severity.HIGH), 1),
            (event("crowdsec", NOW, ip="192.0.2.1", severity=Severity.MEDIUM), 2),
        ]
        summary = build(records)
        self.assertEqual(summary.total_events, 5)
        self.assertEqual((summary.ssh_successes, summary.ssh_failures, summary.ssh_invalid_users), (1, 1, 1))
        self.assertEqual((summary.crowdsec_alerts, summary.unclassified_events), (1, 1))
        self.assertEqual(dict(summary.severity_counts)[Severity.LOW], 2)
        self.assertEqual(dict(summary.severity_counts)[Severity.HIGH], 1)
        self.assertEqual((summary.top_ips[0].ssh_events, summary.top_ips[0].crowdsec_alerts), (2, 1))
        self.assertEqual(summary.top_ips[0].address, "192.0.2.1")

    def test_top_ips_use_structured_valid_ips_and_stable_ties(self) -> None:
        records = [
            (event("linux-auth", NOW, kind="ssh_login_failure", ip="192.0.2.2"), 1),
            (event("linux-auth", NOW, kind="ssh_login_failure", ip="192.0.2.1"), 1),
            (event("linux-auth", NOW, kind="ssh_login_failure", ip="not-an-ip"), 1),
            (event("crowdsec", NOW, ip="192.0.2.3", details=(("source_scope", "Range"),)), 1),
        ]
        summary = build(records)
        self.assertEqual([item.address for item in summary.top_ips], ["192.0.2.1", "192.0.2.2"])

    def test_repeated_failure_threshold_and_evidence_references(self) -> None:
        self.assertEqual(REPEATED_FAILURE_THRESHOLD, 3)
        failures = [
            (event("linux-auth", NOW - timedelta(minutes=minute), kind="ssh_login_failure", ip="192.0.2.1", identity=f"cursor:{minute}"), minute)
            for minute in (1, 2, 3)
        ]
        self.assertEqual(build(failures[:2]).repeated_failures, ())
        finding = build(failures).repeated_failures[0]
        self.assertEqual((finding.address, finding.count), ("192.0.2.1", 3))
        self.assertEqual((finding.first.collection_id, finding.last.collection_id), (3, 1))
        self.assertEqual(finding.first.identity, "cursor:3")

    def test_failure_then_success_requires_source_order_and_inclusive_15_minutes(self) -> None:
        self.assertEqual(FAILURE_SUCCESS_WINDOW, timedelta(minutes=15))
        failure = event("linux-auth", NOW - timedelta(minutes=15), kind="ssh_login_failure", ip="192.0.2.1")
        success = event("linux-auth", NOW, kind="ssh_login_success", ip="192.0.2.1")
        finding = build([(failure, 1), (success, 2)]).failure_then_success[0]
        self.assertEqual((finding.failure.collection_id, finding.success.collection_id), (1, 2))
        too_early = event("linux-auth", NOW - timedelta(minutes=15, microseconds=1), kind="ssh_login_failure", ip="192.0.2.1")
        observed = event("linux-auth", NOW - timedelta(minutes=1), kind="ssh_login_failure", ip="192.0.2.1", basis=TimestampBasis.OBSERVED)
        other_ip = event("linux-auth", NOW - timedelta(minutes=1), kind="ssh_login_failure", ip="192.0.2.2")
        self.assertEqual(build([(too_early, 1), (observed, 2), (other_ip, 3), (success, 4)]).failure_then_success, ())
        observed_success = event("linux-auth", NOW, kind="ssh_login_success", ip="192.0.2.1", basis=TimestampBasis.OBSERVED)
        self.assertEqual(build([(failure, 1), (observed_success, 2)]).failure_then_success, ())
        self.assertEqual(build([(success, 1), (event("linux-auth", NOW + timedelta(minutes=1), kind="ssh_login_failure", ip="192.0.2.1"), 2)]).failure_then_success, ())

    def test_observed_timestamp_and_detection_context_are_preserved(self) -> None:
        detection = event(
            "crowdsec", NOW, ip="192.0.2.1", basis=TimestampBasis.OBSERVED,
            identity="crowdsec:alert:12", severity=Severity.CRITICAL,
            details=(("scenario", "ssh-bf"), ("source_scope", "Ip")),
        )
        summary = build([(detection, 7)])
        self.assertEqual((summary.source_timestamp_count, summary.observed_timestamp_count), (0, 1))
        highlighted = summary.crowdsec_detections[0]
        self.assertEqual((highlighted.scenario, highlighted.source), ("ssh-bf", "Ip 192.0.2.1"))
        self.assertEqual((highlighted.reference.collection_id, highlighted.reference.identity), (7, "crowdsec:alert:12"))

    def test_coverage_uses_collection_timestamps_and_empty_summary_is_immutable(self) -> None:
        runs = (CollectionRun(2, NOW), CollectionRun(1, NOW - timedelta(hours=2)))
        summary = build([], runs)
        self.assertEqual((summary.collection_count, summary.earliest_collection, summary.latest_collection), (2, runs[1].collected_at, NOW))
        self.assertEqual(summary.total_events, 0)
        with self.assertRaises(FrozenInstanceError):
            summary.total_events = 1

    def test_top_five_and_detection_ties_are_stable(self) -> None:
        records = [
            (event("crowdsec", NOW, ip=f"192.0.2.{number}", identity=f"alert:{number}"), number)
            for number in range(1, 8)
        ]
        summary = build(records)
        self.assertEqual([item.address for item in summary.top_ips], [f"192.0.2.{number}" for number in range(1, 6)])
        self.assertEqual([item.reference.collection_id for item in summary.crowdsec_detections], [1, 2, 3, 4, 5])


if __name__ == "__main__":
    unittest.main()
