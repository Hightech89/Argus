"""Shared model behavior tests."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from argus.models import CollectionRun, Evidence, SecurityEvent, Severity, TimestampBasis


_TIMESTAMP = datetime(2026, 9, 24, 14, 30, tzinfo=timezone.utc)
_EVIDENCE = Evidence("crowdsec.alert.latest", "42: ssh-bf", _TIMESTAMP)


class CollectionRunTests(unittest.TestCase):
    def test_collection_run_is_immutable(self) -> None:
        collection = CollectionRun(id=7, collected_at=_TIMESTAMP)

        self.assertEqual(collection.id, 7)
        self.assertEqual(collection.collected_at, _TIMESTAMP)
        with self.assertRaises(FrozenInstanceError):
            collection.id = 8


def _event(**overrides: object) -> SecurityEvent:
    fields: dict[str, object] = {
        "timestamp": _TIMESTAMP,
        "timestamp_basis": TimestampBasis.SOURCE,
        "source": "crowdsec",
        "category": "authentication",
        "severity": Severity.HIGH,
        "summary": "Repeated SSH login attempts",
        "evidence": (_EVIDENCE,),
    }
    fields.update(overrides)
    return SecurityEvent(**fields)


class SecurityEventTests(unittest.TestCase):
    def test_identity_defaults_to_none(self) -> None:
        self.assertIsNone(_event().identity)

    def test_identity_is_generic_and_immutable(self) -> None:
        event = _event(identity="another-source:event:12")

        self.assertEqual(event.identity, "another-source:event:12")
        with self.assertRaises(FrozenInstanceError):
            event.identity = "another-source:event:13"

    def test_identity_requires_a_string_or_none(self) -> None:
        for identity in (12, True, [], {}):
            with self.subTest(identity=identity):
                with self.assertRaisesRegex(TypeError, "identity"):
                    _event(identity=identity)

    def test_creates_event_with_supporting_evidence(self) -> None:
        event = _event()

        self.assertEqual(event.timestamp, _TIMESTAMP)
        self.assertIs(event.timestamp_basis, TimestampBasis.SOURCE)
        self.assertEqual(event.source, "crowdsec")
        self.assertEqual(event.category, "authentication")
        self.assertIs(event.severity, Severity.HIGH)
        self.assertEqual(event.summary, "Repeated SSH login attempts")
        self.assertEqual(event.evidence, (_EVIDENCE,))
        self.assertIs(event.evidence[0], _EVIDENCE)
        self.assertEqual(event.details, ())

    def test_details_are_immutable_ordered_string_pairs(self) -> None:
        details = (("scenario", "crowdsecurity/ssh-bf"), ("event_count", "31"))

        event = _event(details=details)

        self.assertEqual(event.details, details)
        self.assertIs(event.details, details)

    def test_details_require_a_tuple_of_string_pairs(self) -> None:
        invalid_details = (
            [("scenario", "ssh-bf")],
            (("scenario", "ssh-bf", "extra"),),
            (("scenario", 31),),
            ((42, "ssh-bf"),),
        )

        for details in invalid_details:
            with self.subTest(details=details):
                with self.assertRaises(TypeError):
                    _event(details=details)

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

    def test_timestamp_basis_has_stable_values_and_rejects_strings(self) -> None:
        self.assertEqual(
            [str(basis) for basis in TimestampBasis], ["source", "observed"]
        )
        self.assertIs(TimestampBasis("source"), TimestampBasis.SOURCE)
        self.assertIs(TimestampBasis("observed"), TimestampBasis.OBSERVED)
        with self.assertRaises(ValueError):
            TimestampBasis("inferred")
        with self.assertRaises(TypeError):
            _event(timestamp_basis="source")

    def test_requires_timestamp_basis(self) -> None:
        with self.assertRaises(TypeError):
            SecurityEvent(
                timestamp=_TIMESTAMP,
                source="crowdsec",
                category="intrusion",
                severity=Severity.MEDIUM,
                summary="SSH brute force",
                evidence=(_EVIDENCE,),
            )

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
            event.timestamp_basis = TimestampBasis.OBSERVED
        with self.assertRaises(FrozenInstanceError):
            event.evidence[0].content = "Changed"
        with self.assertRaises(FrozenInstanceError):
            event.details = (("scenario", "changed"),)

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
