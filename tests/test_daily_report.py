"""Daily Security Brief rendering tests."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from argus.analysis import EventWindow, build_daily_security_brief
from argus.models import Evidence, SecurityEvent, Severity, TimestampBasis
from argus.report import BULLET, render_daily_security_brief

_START = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
_END = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _event(
    summary: str,
    *,
    basis: TimestampBasis,
    timestamp: datetime | None = None,
    severity: Severity = Severity.MEDIUM,
    category: str = "intrusion",
    details: tuple[tuple[str, str], ...] = (),
) -> SecurityEvent:
    event_time = timestamp or (_END - timedelta(hours=1))
    return SecurityEvent(
        timestamp=event_time,
        timestamp_basis=basis,
        source="test",
        category=category,
        severity=severity,
        summary=summary,
        evidence=(Evidence("test.event", summary, _END),),
        details=details,
    )


def _brief(
    *,
    occurred: tuple[SecurityEvent, ...] = (),
    observed: tuple[SecurityEvent, ...] = (),
):
    return build_daily_security_brief(
        EventWindow(occurred=occurred, observed=observed),
        window_start=_START,
        window_end=_END,
    )


class DailySecurityBriefRendererTests(unittest.TestCase):
    def test_empty_brief_has_stable_zero_event_output(self) -> None:
        report = render_daily_security_brief(_brief())

        self.assertEqual(
            report,
            "\n".join(
                [
                    "ARGUS DAILY SECURITY BRIEF",
                    "",
                    "Window",
                    "2026-10-02T12:00:00+00:00 -> 2026-10-03T12:00:00+00:00",
                    "",
                    "Known Security Events",
                    "Total: 0",
                    "",
                    "Severity",
                    "Info: 0",
                    "Low: 0",
                    "Medium: 0",
                    "High: 0",
                    "Critical: 0",
                    "",
                    "Categories",
                    "None",
                    "",
                    "Recent Events",
                    "None",
                    "",
                    "Observed - Event Time Unknown",
                    "Total: 0",
                    "",
                    "These alerts were observed during the window, but their true occurrence",
                    "time could not be determined.",
                    "",
                    "Severity",
                    "Info: 0",
                    "Low: 0",
                    "Medium: 0",
                    "High: 0",
                    "Critical: 0",
                    "",
                    "Categories",
                    "None",
                    "",
                    "Observed Alerts",
                    "None",
                ]
            ),
        )

    def test_occurred_event_renders_only_as_known_event(self) -> None:
        event = _event(
            "Known SSH activity",
            basis=TimestampBasis.SOURCE,
            severity=Severity.HIGH,
            category="authentication",
        )

        report = render_daily_security_brief(_brief(occurred=(event,)))
        known, observed = report.split("Observed - Event Time Unknown", maxsplit=1)

        self.assertIn("Known Security Events\nTotal: 1", known)
        self.assertIn("authentication: 1", known)
        self.assertIn(
            f"{BULLET} 2026-10-03T11:00:00+00:00 | high | Known SSH activity",
            known,
        )
        self.assertNotIn("Known SSH activity", observed)
        self.assertIn("Observed Alerts\nNone", observed)

    def test_observed_event_renders_only_as_time_unknown(self) -> None:
        event = _event(
            "Observed scan",
            basis=TimestampBasis.OBSERVED,
            severity=Severity.LOW,
            category="network",
        )

        report = render_daily_security_brief(_brief(observed=(event,)))
        known, observed = report.split("Observed - Event Time Unknown", maxsplit=1)

        self.assertIn("Recent Events\nNone", known)
        self.assertNotIn("Observed scan", known)
        self.assertIn("Total: 1", observed)
        self.assertIn("network: 1", observed)
        self.assertIn(
            f"{BULLET} 2026-10-03T11:00:00+00:00 | low | Observed scan",
            observed,
        )

    def test_mixed_event_order_and_summaries_are_preserved(self) -> None:
        occurred_first = _event("First | exact", basis=TimestampBasis.SOURCE)
        occurred_second = _event("Second exact", basis=TimestampBasis.SOURCE)
        observed_first = _event("Observed first", basis=TimestampBasis.OBSERVED)
        observed_second = _event("Observed second", basis=TimestampBasis.OBSERVED)

        report = render_daily_security_brief(
            _brief(
                occurred=(occurred_first, occurred_second),
                observed=(observed_first, observed_second),
            )
        )

        self.assertLess(report.index("First | exact"), report.index("Second exact"))
        self.assertLess(report.index("Observed first"), report.index("Observed second"))
        self.assertEqual(report.count("First | exact"), 1)

    def test_renderer_uses_supplied_counts_and_category_order(self) -> None:
        brief = replace(
            _brief(),
            occurred_count=7,
            occurred_severity_counts=(
                (Severity.INFO, 5),
                (Severity.LOW, 4),
                (Severity.MEDIUM, 3),
                (Severity.HIGH, 2),
                (Severity.CRITICAL, 1),
            ),
            occurred_category_counts=(("zeta", 2), ("alpha", 5)),
        )

        report = render_daily_security_brief(brief)
        known = report.split("Observed - Event Time Unknown", maxsplit=1)[0]

        self.assertIn("Known Security Events\nTotal: 7", known)
        self.assertIn("Info: 5\nLow: 4\nMedium: 3\nHigh: 2\nCritical: 1", known)
        self.assertLess(known.index("zeta: 2"), known.index("alpha: 5"))

    def test_iso_timestamp_preserves_explicit_offset(self) -> None:
        offset = timezone(timedelta(hours=-5))
        event = _event(
            "Offset event",
            basis=TimestampBasis.SOURCE,
            timestamp=datetime(2026, 10, 3, 6, 30, tzinfo=offset),
        )

        report = render_daily_security_brief(_brief(occurred=(event,)))

        self.assertIn("2026-10-03T06:30:00-05:00 | medium | Offset event", report)

    def test_event_details_render_beneath_their_event_in_supplied_order(self) -> None:
        event = _event(
            "SSH brute force",
            basis=TimestampBasis.SOURCE,
            details=(
                ("scenario", "crowdsecurity/ssh-bf"),
                ("source_scope", "Ip"),
                ("source_value", "203.0.113.42"),
                ("country", "US"),
                ("as_number", "AS12345"),
                ("as_name", "Example Network"),
                ("event_count", "31"),
                ("decision_type", "ban"),
                ("decision_duration", "4h"),
            ),
        )

        report = render_daily_security_brief(_brief(occurred=(event,)))

        expected = "\n".join(
            [
                f"{BULLET} 2026-10-03T11:00:00+00:00 | medium | SSH brute force",
                "  Scenario: crowdsecurity/ssh-bf",
                "  Source: Ip 203.0.113.42",
                "  Country: US",
                "  ASN: AS12345 Example Network",
                "  Events: 31",
                "  Decision: ban",
                "  Decision Duration: 4h",
            ]
        )
        self.assertIn(expected, report)

    def test_event_without_details_has_no_detail_lines(self) -> None:
        event = _event("Plain alert", basis=TimestampBasis.SOURCE)

        report = render_daily_security_brief(_brief(occurred=(event,)))

        self.assertIn(
            f"{BULLET} 2026-10-03T11:00:00+00:00 | medium | Plain alert",
            report,
        )
        self.assertNotIn("  Scenario:", report)

    def test_renderer_does_not_mutate_brief_or_events(self) -> None:
        event = _event("Unchanged summary", basis=TimestampBasis.SOURCE)
        brief = _brief(occurred=(event,))
        original_brief = brief
        original_event = event

        render_daily_security_brief(brief)

        self.assertEqual(brief, original_brief)
        self.assertIs(brief.occurred[0], original_event)
        self.assertEqual(event.summary, "Unchanged summary")


if __name__ == "__main__":
    unittest.main()
