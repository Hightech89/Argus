"""Daily Security Brief aggregation tests."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from argus.analysis import DailySecurityBrief, EventWindow, build_daily_security_brief
from argus.models import Evidence, SecurityEvent, Severity, TimestampBasis

_WINDOW_START = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
_WINDOW_END = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
_ZERO_SEVERITIES = tuple((severity, 0) for severity in Severity)


def _event(
    summary: str,
    *,
    basis: TimestampBasis,
    severity: Severity = Severity.MEDIUM,
    category: str = "intrusion",
) -> SecurityEvent:
    evidence = Evidence("test.event", summary, _WINDOW_END)
    return SecurityEvent(
        timestamp=_WINDOW_END - timedelta(hours=1),
        timestamp_basis=basis,
        source="test",
        category=category,
        severity=severity,
        summary=summary,
        evidence=(evidence,),
    )


def _brief(event_window: EventWindow) -> DailySecurityBrief:
    return build_daily_security_brief(
        event_window,
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
    )


class DailySecurityBriefTests(unittest.TestCase):
    def test_empty_window_has_stable_zero_aggregates(self) -> None:
        brief = _brief(EventWindow(occurred=(), observed=()))

        self.assertEqual(brief.window_start, _WINDOW_START)
        self.assertEqual(brief.window_end, _WINDOW_END)
        self.assertEqual(brief.occurred_count, 0)
        self.assertEqual(brief.observed_count, 0)
        self.assertEqual(brief.occurred, ())
        self.assertEqual(brief.observed, ())
        self.assertEqual(brief.occurred_severity_counts, _ZERO_SEVERITIES)
        self.assertEqual(brief.observed_severity_counts, _ZERO_SEVERITIES)
        self.assertEqual(brief.occurred_category_counts, ())
        self.assertEqual(brief.observed_category_counts, ())

    def test_one_occurred_event_is_aggregated_separately(self) -> None:
        event = _event(
            "Known occurrence",
            basis=TimestampBasis.SOURCE,
            severity=Severity.HIGH,
            category="authentication",
        )

        brief = _brief(EventWindow(occurred=(event,), observed=()))

        self.assertEqual(brief.occurred_count, 1)
        self.assertEqual(brief.observed_count, 0)
        self.assertEqual(brief.occurred, (event,))
        self.assertEqual(dict(brief.occurred_severity_counts)[Severity.HIGH], 1)
        self.assertEqual(
            brief.occurred_category_counts, (("authentication", 1),)
        )

    def test_one_observed_event_is_aggregated_separately(self) -> None:
        event = _event(
            "Observed only",
            basis=TimestampBasis.OBSERVED,
            severity=Severity.LOW,
            category="network",
        )

        brief = _brief(EventWindow(occurred=(), observed=(event,)))

        self.assertEqual(brief.occurred_count, 0)
        self.assertEqual(brief.observed_count, 1)
        self.assertEqual(brief.occurred, ())
        self.assertEqual(brief.observed, (event,))
        self.assertEqual(dict(brief.observed_severity_counts)[Severity.LOW], 1)
        self.assertEqual(brief.observed_category_counts, (("network", 1),))

    def test_mixed_counts_and_event_order_remain_separate(self) -> None:
        occurred_first = _event(
            "Occurred first", basis=TimestampBasis.SOURCE, severity=Severity.INFO
        )
        occurred_second = _event(
            "Occurred second", basis=TimestampBasis.SOURCE, severity=Severity.CRITICAL
        )
        observed_first = _event(
            "Observed first", basis=TimestampBasis.OBSERVED, severity=Severity.HIGH
        )
        observed_second = _event(
            "Observed second", basis=TimestampBasis.OBSERVED, severity=Severity.HIGH
        )

        brief = _brief(
            EventWindow(
                occurred=(occurred_first, occurred_second),
                observed=(observed_first, observed_second),
            )
        )

        self.assertEqual(brief.occurred_count, 2)
        self.assertEqual(brief.observed_count, 2)
        self.assertEqual(brief.occurred, (occurred_first, occurred_second))
        self.assertEqual(brief.observed, (observed_first, observed_second))
        self.assertEqual(dict(brief.occurred_severity_counts)[Severity.HIGH], 0)
        self.assertEqual(dict(brief.observed_severity_counts)[Severity.HIGH], 2)

    def test_all_severity_levels_are_present_in_enum_order(self) -> None:
        event = _event(
            "Medium event", basis=TimestampBasis.SOURCE, severity=Severity.MEDIUM
        )

        brief = _brief(EventWindow(occurred=(event,), observed=()))

        self.assertEqual(
            brief.occurred_severity_counts,
            (
                (Severity.INFO, 0),
                (Severity.LOW, 0),
                (Severity.MEDIUM, 1),
                (Severity.HIGH, 0),
                (Severity.CRITICAL, 0),
            ),
        )

    def test_category_counts_are_flexible_sorted_and_aggregated(self) -> None:
        zeta_first = _event(
            "Zeta first", basis=TimestampBasis.SOURCE, category="zeta/custom"
        )
        alpha = _event(
            "Alpha", basis=TimestampBasis.SOURCE, category="authentication"
        )
        zeta_second = _event(
            "Zeta second", basis=TimestampBasis.SOURCE, category="zeta/custom"
        )

        brief = _brief(
            EventWindow(occurred=(zeta_first, alpha, zeta_second), observed=())
        )

        self.assertEqual(
            brief.occurred_category_counts,
            (("authentication", 1), ("zeta/custom", 2)),
        )
        self.assertEqual(brief.occurred, (zeta_first, alpha, zeta_second))

    def test_timezone_offset_window_bounds_are_accepted(self) -> None:
        central = timezone(timedelta(hours=-5))
        eastern_europe = timezone(timedelta(hours=2))
        start = datetime(2026, 10, 3, 7, 0, tzinfo=central)
        end = datetime(2026, 10, 3, 15, 0, tzinfo=eastern_europe)

        brief = build_daily_security_brief(
            EventWindow(occurred=(), observed=()),
            window_start=start,
            window_end=end,
        )

        self.assertIs(brief.window_start, start)
        self.assertIs(brief.window_end, end)

    def test_naive_window_start_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_daily_security_brief(
                EventWindow(occurred=(), observed=()),
                window_start=datetime(2026, 10, 2, 12, 0),
                window_end=_WINDOW_END,
            )

    def test_naive_window_end_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_daily_security_brief(
                EventWindow(occurred=(), observed=()),
                window_start=_WINDOW_START,
                window_end=datetime(2026, 10, 3, 12, 0),
            )

    def test_start_after_end_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_daily_security_brief(
                EventWindow(occurred=(), observed=()),
                window_start=_WINDOW_END,
                window_end=_WINDOW_START,
            )

    def test_inputs_are_not_mutated_and_result_is_immutable(self) -> None:
        event = _event("Unchanged", basis=TimestampBasis.SOURCE)
        event_window = EventWindow(occurred=(event, event), observed=())
        original_occurred = event_window.occurred
        original_summary = event.summary

        brief = _brief(event_window)

        self.assertIs(event_window.occurred, original_occurred)
        self.assertEqual(event.summary, original_summary)
        self.assertEqual(brief.occurred, (event, event))
        self.assertEqual(brief.occurred_count, 2)
        self.assertIs(brief.occurred[0], event)
        with self.assertRaises(FrozenInstanceError):
            brief.occurred_count = 0


if __name__ == "__main__":
    unittest.main()
