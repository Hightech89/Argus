"""Security event rolling-window tests."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

from argus.analysis import (
    EventWindow,
    deduplicate_events,
    select_event_window,
    select_historical_event_window,
)
from argus.models import Evidence, SecurityEvent, Severity, TimestampBasis

_NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _event(
    summary: str,
    timestamp: datetime,
    basis: TimestampBasis = TimestampBasis.SOURCE,
) -> SecurityEvent:
    evidence = Evidence("test.event", summary, _NOW)
    return SecurityEvent(
        timestamp=timestamp,
        timestamp_basis=basis,
        source="test",
        category="intrusion",
        severity=Severity.MEDIUM,
        summary=summary,
        evidence=(evidence,),
    )


class DeduplicateEventsTests(unittest.TestCase):
    def test_empty_iterable_returns_empty_tuple(self) -> None:
        self.assertEqual(deduplicate_events(iter(())), ())

    def test_keyed_duplicates_keep_first_input_occurrence(self) -> None:
        first = replace(_event("first", _NOW), identity="test:event:12")
        second = replace(
            _event("enriched later", _NOW + timedelta(minutes=1)),
            identity="test:event:12",
            details=(("context", "new"),),
        )

        result = deduplicate_events([first, second])

        self.assertEqual(result, (first,))
        self.assertIs(result[0], first)
        self.assertIs(deduplicate_events([second, first])[0], second)

    def test_unkeyed_events_are_never_deduplicated(self) -> None:
        first = _event("same", _NOW)
        equal_but_distinct = _event("same", _NOW)

        result = deduplicate_events([first, first, equal_but_distinct])

        self.assertEqual(len(result), 3)
        self.assertIs(result[0], first)
        self.assertIs(result[1], first)
        self.assertIs(result[2], equal_but_distinct)

    def test_mixed_ordering_and_distinct_source_identities_are_preserved(self) -> None:
        unkeyed = _event("unkeyed", _NOW)
        first = replace(_event("keyed first", _NOW), identity="test:event:12")
        duplicate = replace(_event("keyed duplicate", _NOW), identity=first.identity)
        other = replace(_event("other source", _NOW), identity="other:event:12")

        result = deduplicate_events(iter([unkeyed, first, duplicate, unkeyed, other]))

        self.assertEqual(result, (unkeyed, first, unkeyed, other))

    def test_input_events_and_supporting_evidence_are_not_mutated_or_merged(self) -> None:
        first = replace(_event("first", _NOW), identity="test:event:12")
        second = replace(_event("second", _NOW), identity=first.identity)
        events = [first, second]
        before = tuple(events)
        first_evidence = first.evidence
        second_evidence = second.evidence

        result = deduplicate_events(events)

        self.assertEqual(tuple(events), before)
        self.assertIs(result[0], first)
        self.assertIs(first.evidence, first_evidence)
        self.assertIs(second.evidence, second_evidence)
        self.assertEqual(first.evidence[0].content, "first")
        self.assertEqual(second.evidence[0].content, "second")

    def test_return_value_is_an_immutable_tuple(self) -> None:
        event = _event("unkeyed", _NOW)
        result = deduplicate_events([event])

        self.assertIsInstance(result, tuple)
        with self.assertRaises(TypeError):
            result[0] = _event("changed", _NOW)


class EventWindowTests(unittest.TestCase):
    def test_empty_input_returns_empty_immutable_buckets(self) -> None:
        result = select_event_window([], now=_NOW)

        self.assertEqual(result, EventWindow(occurred=(), observed=()))
        with self.assertRaises(FrozenInstanceError):
            result.occurred = (_event("changed", _NOW),)

    def test_source_event_inside_window_is_occurred(self) -> None:
        event = _event("source", _NOW - timedelta(hours=1))

        result = select_event_window([event], now=_NOW)

        self.assertEqual(result.occurred, (event,))
        self.assertEqual(result.observed, ())

    def test_observed_event_inside_window_is_only_observed(self) -> None:
        event = _event(
            "observed",
            _NOW - timedelta(hours=1),
            TimestampBasis.OBSERVED,
        )

        result = select_event_window([event], now=_NOW)

        self.assertEqual(result.occurred, ())
        self.assertEqual(result.observed, (event,))
        self.assertNotIn(event, result.occurred)

    def test_cutoff_and_now_boundaries_are_inclusive(self) -> None:
        at_cutoff = _event("cutoff", _NOW - timedelta(hours=24))
        at_now = _event("now", _NOW, TimestampBasis.OBSERVED)

        result = select_event_window([at_cutoff, at_now], now=_NOW)

        self.assertEqual(result.occurred, (at_cutoff,))
        self.assertEqual(result.observed, (at_now,))

    def test_old_and_future_events_are_excluded(self) -> None:
        old = _event("old", _NOW - timedelta(hours=24, microseconds=1))
        future = _event(
            "future",
            _NOW + timedelta(microseconds=1),
            TimestampBasis.OBSERVED,
        )

        result = select_event_window([old, future], now=_NOW)

        self.assertEqual(result, EventWindow(occurred=(), observed=()))

    def test_mixed_events_preserve_order_and_are_not_mutated(self) -> None:
        observed_first = _event(
            "observed first", _NOW - timedelta(hours=4), TimestampBasis.OBSERVED
        )
        source_first = _event("source first", _NOW - timedelta(hours=3))
        observed_second = _event(
            "observed second", _NOW - timedelta(hours=2), TimestampBasis.OBSERVED
        )
        source_second = _event("source second", _NOW - timedelta(hours=1))
        events = [observed_first, source_first, observed_second, source_second]
        original = tuple(events)

        result = select_event_window(iter(events), now=_NOW)

        self.assertEqual(result.occurred, (source_first, source_second))
        self.assertEqual(result.observed, (observed_first, observed_second))
        self.assertEqual(tuple(events), original)
        self.assertIs(result.occurred[0], source_first)
        self.assertIs(result.observed[0], observed_first)

    def test_timezone_offsets_compare_by_absolute_time(self) -> None:
        central = timezone(timedelta(hours=-5))
        inside = _event("inside", datetime(2026, 10, 3, 6, 30, tzinfo=central))
        before_cutoff = _event(
            "before cutoff", datetime(2026, 10, 2, 6, 59, tzinfo=central)
        )

        result = select_event_window([inside, before_cutoff], now=_NOW)

        self.assertEqual(result.occurred, (inside,))

    def test_naive_now_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            select_event_window([], now=datetime(2026, 10, 3, 12, 0))

    def test_non_datetime_now_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            select_event_window([], now="2026-10-03T12:00:00Z")

    def test_zero_and_negative_windows_are_rejected(self) -> None:
        for window in (timedelta(0), timedelta(microseconds=-1)):
            with self.subTest(window=window):
                with self.assertRaises(ValueError):
                    select_event_window([], now=_NOW, window=window)


class HistoricalEventWindowTests(unittest.TestCase):
    def test_inclusive_boundaries_and_collection_attribution(self) -> None:
        cutoff = _NOW - timedelta(hours=24)
        at_cutoff = _event("cutoff", cutoff)
        at_now = _event("now", _NOW, TimestampBasis.OBSERVED)
        old = _event("old", cutoff - timedelta(microseconds=1))
        future = _event("future", _NOW + timedelta(microseconds=1))
        records = [(old, 1), (at_cutoff, 2), (at_now, 3), (future, 4)]

        result = select_historical_event_window(iter(records), now=_NOW, window=timedelta(hours=24))

        self.assertEqual(result, ((at_cutoff, 2), (at_now, 3)))
        self.assertIsInstance(result, tuple)
        self.assertIs(result[0][0], at_cutoff)
        self.assertEqual(records[1], (at_cutoff, 2))

    def test_basis_does_not_change_timestamp_selection(self) -> None:
        inside = _NOW - timedelta(hours=1)
        source = _event("source", inside)
        observed = _event("observed", inside, TimestampBasis.OBSERVED)
        result = select_historical_event_window(
            [(source, 99), (observed, 1)], now=_NOW, window=timedelta(hours=24)
        )
        self.assertEqual(result, ((source, 99), (observed, 1)))

    def test_invalid_clock_and_window_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            select_historical_event_window([], now=_NOW.replace(tzinfo=None), window=timedelta(hours=1))
        with self.assertRaises(TypeError):
            select_historical_event_window([], now="today", window=timedelta(hours=1))
        with self.assertRaises(ValueError):
            select_historical_event_window([], now=_NOW, window=timedelta(0))
        with self.assertRaises(TypeError):
            select_historical_event_window([], now=_NOW, window=1)


if __name__ == "__main__":
    unittest.main()
