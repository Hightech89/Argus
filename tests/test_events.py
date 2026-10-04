"""Evidence-to-event interpretation tests."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from argus.events import crowdsec_event_from_evidence
from argus.models import Evidence, Severity

_OBSERVED_AT = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


class CrowdSecEventTests(unittest.TestCase):
    def test_complete_alert_converts_to_security_event(self) -> None:
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
            [unrelated, latest, reason, timestamp]
        )

        self.assertIsNotNone(event)
        self.assertEqual(event.source, "crowdsec")
        self.assertEqual(event.category, "intrusion")
        self.assertIs(event.severity, Severity.MEDIUM)
        self.assertEqual(event.summary, "SSH brute force")
        self.assertEqual(
            event.timestamp, datetime(2026, 10, 3, 11, 45, tzinfo=timezone.utc)
        )
        self.assertIs(event.timestamp.tzinfo, timezone.utc)
        self.assertEqual(event.evidence, (latest, reason, timestamp))
        self.assertIs(event.evidence[0], latest)
        self.assertNotIn(unrelated, event.evidence)

    def test_latest_alert_content_is_summary_when_reason_is_missing(self) -> None:
        latest = Evidence(
            "crowdsec.alert.latest", "42: crowdsecurity/ssh-bf", _OBSERVED_AT
        )

        event = crowdsec_event_from_evidence([latest])

        self.assertIsNotNone(event)
        self.assertEqual(event.summary, latest.content)
        self.assertEqual(event.timestamp, _OBSERVED_AT)
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
