"""Shared model behavior tests."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from argus.models import Evidence, SecurityEvent, Severity


_TIMESTAMP = datetime(2026, 9, 24, 14, 30, tzinfo=timezone.utc)
_EVIDENCE = Evidence("crowdsec.alert.latest", "42: ssh-bf", _TIMESTAMP)


def _event(**overrides: object) -> SecurityEvent:
    fields: dict[str, object] = {
        "timestamp": _TIMESTAMP,
        "source": "crowdsec",
        "category": "authentication",
        "severity": Severity.HIGH,
        "summary": "Repeated SSH login attempts",
        "evidence": (_EVIDENCE,),
    }
    fields.update(overrides)
    return SecurityEvent(**fields)


class SecurityEventTests(unittest.TestCase):
    def test_creates_event_with_supporting_evidence(self) -> None:
        event = _event()

        self.assertEqual(event.timestamp, _TIMESTAMP)
        self.assertEqual(event.source, "crowdsec")
        self.assertEqual(event.category, "authentication")
        self.assertIs(event.severity, Severity.HIGH)
        self.assertEqual(event.summary, "Repeated SSH login attempts")
        self.assertEqual(event.evidence, (_EVIDENCE,))
        self.assertIs(event.evidence[0], _EVIDENCE)

    def test_multiple_evidence_records_remain_associated_in_order(self) -> None:
        second = Evidence("crowdsec.alert.latest_reason", "SSH brute force")
        event = _event(evidence=(_EVIDENCE, second))

        self.assertEqual(event.evidence, (_EVIDENCE, second))

    def test_category_is_not_limited_to_a_fixed_taxonomy(self) -> None:
        event = _event(category="container/service health")

        self.assertEqual(event.category, "container/service health")

    def test_severity_levels_have_stable_string_values(self) -> None:
        self.assertEqual(
            [str(level) for level in Severity],
            ["info", "low", "medium", "high", "critical"],
        )
        self.assertIs(Severity("high"), Severity.HIGH)
        with self.assertRaises(ValueError):
            Severity("urgent")

    def test_rejects_arbitrary_severity_strings(self) -> None:
        with self.assertRaises(TypeError):
            _event(severity="high")

    def test_requires_at_least_one_evidence_record(self) -> None:
        with self.assertRaises(ValueError):
            _event(evidence=())

    def test_requires_immutable_evidence_tuple_of_records(self) -> None:
        with self.assertRaises(TypeError):
            _event(evidence=[_EVIDENCE])
        with self.assertRaises(TypeError):
            _event(evidence=(_EVIDENCE, "not evidence"))

    def test_event_and_evidence_cannot_be_reassigned(self) -> None:
        event = _event()

        with self.assertRaises(FrozenInstanceError):
            event.summary = "Changed"
        with self.assertRaises(FrozenInstanceError):
            event.evidence[0].content = "Changed"

    def test_preserves_timezone_aware_timestamp(self) -> None:
        offset = timezone(timedelta(hours=-5))
        timestamp = datetime(2026, 9, 24, 9, 30, tzinfo=offset)

        event = _event(timestamp=timestamp)

        self.assertIs(event.timestamp, timestamp)
        self.assertEqual(event.timestamp.astimezone(timezone.utc), _TIMESTAMP)

    def test_rejects_naive_or_non_datetime_timestamp(self) -> None:
        with self.assertRaises(ValueError):
            _event(timestamp=datetime(2026, 9, 24, 14, 30))
        with self.assertRaises(TypeError):
            _event(timestamp="2026-09-24T14:30:00Z")


if __name__ == "__main__":
    unittest.main()
