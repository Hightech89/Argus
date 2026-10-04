"""Evidence-to-event interpretation tests."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from argus.events import crowdsec_event_from_evidence, crowdsec_events_from_evidence
from argus.models import Evidence, Severity, TimestampBasis

_OBSERVED_AT = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _raw(alert: object, observed_at: datetime | None = _OBSERVED_AT) -> Evidence:
    return Evidence(
        "crowdsec.alert.raw",
        json.dumps(alert, sort_keys=True, separators=(",", ":")),
        observed_at,
    )


class CrowdSecRawEventsTests(unittest.TestCase):
    def test_zero_raw_alerts_and_unrelated_evidence_return_empty_list(self) -> None:
        evidence = [
            Evidence("crowdsec.available", "true", _OBSERVED_AT),
            Evidence("crowdsec.alert.latest", "42: ssh-bf", _OBSERVED_AT),
            Evidence("docker.container.running", "crowdsec", _OBSERVED_AT),
        ]

        self.assertEqual(crowdsec_events_from_evidence(evidence), [])

    def test_one_raw_alert_produces_one_traceable_event(self) -> None:
        record = _raw(
            {
                "created_at": "2026-10-03T11:45:00Z",
                "message": "SSH brute force",
                "reason": "Repeated authentication failures",
                "scenario": "crowdsecurity/ssh-bf",
            }
        )

        events = crowdsec_events_from_evidence([record])

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.source, "crowdsec")
        self.assertEqual(event.category, "intrusion")
        self.assertIs(event.severity, Severity.MEDIUM)
        self.assertEqual(event.summary, "SSH brute force")
        self.assertEqual(
            event.timestamp, datetime(2026, 10, 3, 11, 45, tzinfo=timezone.utc)
        )
        self.assertIs(event.timestamp_basis, TimestampBasis.SOURCE)
        self.assertIs(event.timestamp.tzinfo, timezone.utc)
        self.assertEqual(event.evidence, (record,))
        self.assertIs(event.evidence[0], record)

    def test_multiple_events_preserve_input_order_and_origin(self) -> None:
        first = _raw(
            {"message": "First alert", "created_at": "2026-10-03T10:00:00Z"}
        )
        second = _raw(
            {"message": "Second alert", "created_at": "2026-10-03T11:00:00Z"}
        )

        events = crowdsec_events_from_evidence([second, first])

        self.assertEqual(
            [event.summary for event in events], ["Second alert", "First alert"]
        )
        self.assertIs(events[0].evidence[0], second)
        self.assertIs(events[1].evidence[0], first)
        self.assertTrue(all(len(event.evidence) == 1 for event in events))

    def test_summary_fallbacks_are_deterministic(self) -> None:
        cases = [
            (
                {"message": " ", "reason": "Blocked source", "scenario": "ssh-bf"},
                "Blocked source",
            ),
            (
                {"message": 42, "reason": " ", "scenario": "crowdsecurity/ssh-bf"},
                "crowdsecurity/ssh-bf",
            ),
            ({"message": " ", "reason": None}, "CrowdSec alert"),
        ]

        for alert, expected in cases:
            with self.subTest(expected=expected):
                event = crowdsec_events_from_evidence([_raw(alert)])[0]
                self.assertEqual(event.summary, expected)

    def test_alternate_native_timestamp_fields_are_used_in_order(self) -> None:
        for field in ("start_at", "stop_at", "updated_at"):
            with self.subTest(field=field):
                record = _raw(
                    {
                        "created_at": "invalid",
                        field: "2026-10-03T11:45:00Z",
                    }
                )
                event = crowdsec_events_from_evidence([record])[0]
                self.assertEqual(
                    event.timestamp,
                    datetime(2026, 10, 3, 11, 45, tzinfo=timezone.utc),
                )

        preferred = _raw(
            {
                "created_at": "2026-10-03T09:00:00Z",
                "start_at": "2026-10-03T10:00:00Z",
                "stop_at": "2026-10-03T11:00:00Z",
                "updated_at": "2026-10-03T12:00:00Z",
            }
        )
        event = crowdsec_events_from_evidence([preferred])[0]
        self.assertEqual(
            event.timestamp, datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
        )

    def test_explicit_timestamp_offset_is_preserved(self) -> None:
        native_time = "2026-10-03T06:45:00-05:00"

        event = crowdsec_events_from_evidence(
            [_raw({"created_at": native_time})]
        )[0]

        self.assertEqual(event.timestamp, datetime.fromisoformat(native_time))
        self.assertEqual(event.timestamp.utcoffset(), timedelta(hours=-5))

    def test_missing_native_timestamp_uses_observed_at(self) -> None:
        record = _raw({"message": "Observed alert"})

        event = crowdsec_events_from_evidence([record])[0]

        self.assertIs(event.timestamp, _OBSERVED_AT)
        self.assertIs(event.timestamp_basis, TimestampBasis.OBSERVED)

    def test_naive_or_unusable_native_timestamp_uses_observed_at(self) -> None:
        for value in ("2026-10-03T11:45:00", "not-a-timestamp", 42):
            with self.subTest(value=value):
                event = crowdsec_events_from_evidence(
                    [_raw({"created_at": value})]
                )[0]
                self.assertIs(event.timestamp, _OBSERVED_AT)
                self.assertIs(event.timestamp_basis, TimestampBasis.OBSERVED)

    def test_invalid_json_and_non_object_json_are_skipped(self) -> None:
        valid = _raw({"message": "Valid alert"})
        records = [
            Evidence("crowdsec.alert.raw", "{invalid", _OBSERVED_AT),
            _raw([{"message": "Nested alert"}]),
            _raw("not an object"),
            valid,
        ]

        events = crowdsec_events_from_evidence(records)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].summary, "Valid alert")
        self.assertIs(events[0].evidence[0], valid)

    def test_missing_all_usable_timestamps_skips_only_that_alert(self) -> None:
        missing_time = _raw({"message": "No usable time"}, observed_at=None)
        naive_time = _raw(
            {"created_at": "2026-10-03T11:45:00"},
            observed_at=datetime(2026, 10, 3, 12, 0),
        )
        valid = _raw({"message": "Valid alert"})

        events = crowdsec_events_from_evidence([missing_time, valid, naive_time])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].summary, "Valid alert")
        self.assertIs(events[0].evidence[0], valid)


class CrowdSecEventTests(unittest.TestCase):
    def test_complete_alert_converts_to_security_event(self) -> None:
        raw = _raw(
            {"created_at": "2026-10-03T11:30:00Z", "message": "Raw alert"}
        )
        latest = Evidence(
            "crowdsec.alert.latest", "42: crowdsecurity/ssh-bf", _OBSERVED_AT
        )
        reason = Evidence(
            "crowdsec.alert.latest_reason", "SSH brute force", _OBSERVED_AT
        )
        timestamp = Evidence(
            "crowdsec.alert.latest_timestamp",
            "2026-10-03T11:45:00Z",
            _OBSERVED_AT,
        )
        unrelated = Evidence("crowdsec.api_healthy", "true", _OBSERVED_AT)

        event = crowdsec_event_from_evidence(
            [raw, unrelated, latest, reason, timestamp]
        )

        self.assertIsNotNone(event)
        self.assertEqual(event.source, "crowdsec")
        self.assertEqual(event.category, "intrusion")
        self.assertIs(event.severity, Severity.MEDIUM)
        self.assertEqual(event.summary, "SSH brute force")
        self.assertEqual(
            event.timestamp, datetime(2026, 10, 3, 11, 45, tzinfo=timezone.utc)
        )
        self.assertIs(event.timestamp_basis, TimestampBasis.SOURCE)
        self.assertIs(event.timestamp.tzinfo, timezone.utc)
        self.assertEqual(event.evidence, (latest, reason, timestamp))
        self.assertIs(event.evidence[0], latest)
        self.assertNotIn(raw, event.evidence)
        self.assertNotIn(unrelated, event.evidence)

    def test_latest_alert_content_is_summary_when_reason_is_missing(self) -> None:
        latest = Evidence(
            "crowdsec.alert.latest", "42: crowdsecurity/ssh-bf", _OBSERVED_AT
        )

        event = crowdsec_event_from_evidence([latest])

        self.assertIsNotNone(event)
        self.assertEqual(event.summary, latest.content)
        self.assertEqual(event.timestamp, _OBSERVED_AT)
        self.assertIs(event.timestamp_basis, TimestampBasis.OBSERVED)
        self.assertEqual(event.evidence, (latest,))

    def test_native_timestamp_with_offset_is_preserved(self) -> None:
        native_time = "2026-10-03T06:45:00-05:00"
        evidence = [
            Evidence("crowdsec.alert.latest", "42: ssh-bf", _OBSERVED_AT),
            Evidence("crowdsec.alert.latest_timestamp", native_time, _OBSERVED_AT),
        ]

        event = crowdsec_event_from_evidence(evidence)

        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp, datetime.fromisoformat(native_time))
        self.assertIs(event.timestamp_basis, TimestampBasis.SOURCE)
        self.assertEqual(event.timestamp.utcoffset(), timedelta(hours=-5))

    def test_missing_latest_alert_returns_none(self) -> None:
        evidence = [
            Evidence("crowdsec.alert.latest_reason", "SSH brute force", _OBSERVED_AT),
            Evidence(
                "crowdsec.alert.latest_timestamp",
                "2026-10-03T11:45:00Z",
                _OBSERVED_AT,
            ),
        ]

        self.assertIsNone(crowdsec_event_from_evidence(evidence))

    def test_missing_native_timestamp_uses_aware_observed_at(self) -> None:
        latest = Evidence("crowdsec.alert.latest", "42: ssh-bf", None)
        reason = Evidence(
            "crowdsec.alert.latest_reason", "SSH brute force", _OBSERVED_AT
        )

        event = crowdsec_event_from_evidence(iter([latest, reason]))

        self.assertIsNotNone(event)
        self.assertIs(event.timestamp, _OBSERVED_AT)
        self.assertIs(event.timestamp_basis, TimestampBasis.OBSERVED)

    def test_unusable_native_timestamp_uses_aware_observed_at(self) -> None:
        evidence = [
            Evidence("crowdsec.alert.latest", "42: ssh-bf", _OBSERVED_AT),
            Evidence(
                "crowdsec.alert.latest_timestamp", "not-a-timestamp", _OBSERVED_AT
            ),
        ]

        event = crowdsec_event_from_evidence(evidence)

        self.assertIsNotNone(event)
        self.assertIs(event.timestamp, _OBSERVED_AT)
        self.assertIs(event.timestamp_basis, TimestampBasis.OBSERVED)

    def test_naive_native_timestamp_uses_aware_observed_at(self) -> None:
        evidence = [
            Evidence("crowdsec.alert.latest", "42: ssh-bf", _OBSERVED_AT),
            Evidence(
                "crowdsec.alert.latest_timestamp",
                "2026-10-03T11:45:00",
                _OBSERVED_AT,
            ),
        ]

        event = crowdsec_event_from_evidence(evidence)

        self.assertIsNotNone(event)
        self.assertIs(event.timestamp, _OBSERVED_AT)
        self.assertIs(event.timestamp_basis, TimestampBasis.OBSERVED)

    def test_unusable_timestamp_without_aware_fallback_returns_none(self) -> None:
        naive_observation = datetime(2026, 10, 3, 12, 0)
        evidence = [
            Evidence("crowdsec.alert.latest", "42: ssh-bf", naive_observation),
            Evidence(
                "crowdsec.alert.latest_timestamp", "not-a-timestamp", None
            ),
        ]

        self.assertIsNone(crowdsec_event_from_evidence(evidence))


if __name__ == "__main__":
    unittest.main()
