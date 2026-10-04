"""Command-line interface tests."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from typer.testing import CliRunner

from argus.cli import _utc_now, app
from argus.models import Evidence

_NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _raw_alert(
    summary: str,
    *,
    timestamp: datetime | None = None,
    observed_at: datetime | None = None,
) -> Evidence:
    alert = {"message": summary}
    if timestamp is not None:
        alert["created_at"] = timestamp.isoformat()
    return Evidence(
        source="crowdsec.alert.raw",
        content=json.dumps(alert),
        observed_at=observed_at,
    )


class DailyCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def _invoke_daily(self, evidence: list[Evidence]):
        with (
            patch("argus.cli._utc_now", return_value=_NOW) as clock,
            patch(
                "argus.cli.collect_crowdsec_evidence", return_value=evidence
            ) as collector,
        ):
            result = self.runner.invoke(app, ["daily"])
        self.assertEqual(result.exit_code, 0, result.output)
        clock.assert_called_once_with()
        collector.assert_called_once_with()
        return result

    def test_daily_command_exists(self) -> None:
        result = self.runner.invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("daily", result.output)

    def test_clock_helper_returns_timezone_aware_utc(self) -> None:
        now = _utc_now()

        self.assertIs(now.tzinfo, timezone.utc)
        self.assertEqual(now.utcoffset(), timedelta(0))

    def test_zero_alerts_render_zero_event_brief(self) -> None:
        result = self._invoke_daily([])

        self.assertIn("ARGUS DAILY SECURITY BRIEF", result.output)
        self.assertIn("Known Security Events\nTotal: 0", result.output)
        self.assertIn("Observed - Event Time Unknown\nTotal: 0", result.output)

    def test_source_timed_event_renders_as_known(self) -> None:
        result = self._invoke_daily(
            [_raw_alert("Known alert", timestamp=_NOW - timedelta(hours=1))]
        )
        known, observed = result.output.split(
            "Observed - Event Time Unknown", maxsplit=1
        )

        self.assertIn("Known Security Events\nTotal: 1", known)
        self.assertIn("Known alert", known)
        self.assertNotIn("Known alert", observed)

    def test_observed_fallback_event_renders_only_as_observed(self) -> None:
        result = self._invoke_daily(
            [_raw_alert("Observed alert", observed_at=_NOW - timedelta(hours=1))]
        )
        known, observed = result.output.split(
            "Observed - Event Time Unknown", maxsplit=1
        )

        self.assertNotIn("Observed alert", known)
        self.assertIn("Total: 1", observed)
        self.assertIn("Observed alert", observed)

    def test_collection_precedes_clock_and_includes_observation_from_collection(
        self,
    ) -> None:
        call_order: list[str] = []

        def collect() -> list[Evidence]:
            call_order.append("collect")
            return [
                _raw_alert(
                    "Collected fallback alert",
                    observed_at=_NOW - timedelta(microseconds=1),
                )
            ]

        def clock() -> datetime:
            call_order.append("clock")
            return _NOW

        with (
            patch("argus.cli.collect_crowdsec_evidence", side_effect=collect),
            patch("argus.cli._utc_now", side_effect=clock) as clock_mock,
        ):
            result = self.runner.invoke(app, ["daily"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(call_order, ["collect", "clock"])
        clock_mock.assert_called_once_with()
        known, observed = result.output.split(
            "Observed - Event Time Unknown", maxsplit=1
        )
        self.assertNotIn("Collected fallback alert", known)
        self.assertIn("Total: 1", observed)
        self.assertIn("Collected fallback alert", observed)

    def test_events_outside_window_are_excluded(self) -> None:
        evidence = [
            _raw_alert("Too old", timestamp=_NOW - timedelta(hours=25)),
            _raw_alert("In the future", timestamp=_NOW + timedelta(seconds=1)),
        ]

        result = self._invoke_daily(evidence)

        self.assertIn("Known Security Events\nTotal: 0", result.output)
        self.assertNotIn("Too old", result.output)
        self.assertNotIn("In the future", result.output)

    def test_multiple_events_flow_through_in_order(self) -> None:
        evidence = [
            _raw_alert("First known", timestamp=_NOW - timedelta(hours=2)),
            _raw_alert("Second known", timestamp=_NOW - timedelta(hours=1)),
            _raw_alert("Observed only", observed_at=_NOW - timedelta(minutes=30)),
        ]

        result = self._invoke_daily(evidence)

        self.assertIn("Known Security Events\nTotal: 2", result.output)
        self.assertIn("Observed - Event Time Unknown\nTotal: 1", result.output)
        self.assertLess(
            result.output.index("First known"), result.output.index("Second known")
        )

    def test_one_now_value_defines_both_window_boundaries(self) -> None:
        result = self._invoke_daily([])

        self.assertIn(
            "2026-10-02T12:00:00+00:00 -> 2026-10-03T12:00:00+00:00",
            result.output,
        )

    def test_command_prints_existing_renderer_output(self) -> None:
        with (
            patch("argus.cli._utc_now", return_value=_NOW),
            patch("argus.cli.collect_crowdsec_evidence", return_value=[]),
            patch(
                "argus.cli.render_daily_security_brief",
                return_value="rendered daily brief",
            ) as renderer,
        ):
            result = self.runner.invoke(app, ["daily"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output, "rendered daily brief\n")
        renderer.assert_called_once()


class BriefCommandRegressionTests(unittest.TestCase):
    def test_brief_pipeline_is_unchanged(self) -> None:
        docker_evidence = [Evidence("docker.installed", "true")]
        crowdsec_evidence = [Evidence("crowdsec.available", "true")]

        with (
            patch(
                "argus.cli.collect_docker_evidence", return_value=docker_evidence
            ) as docker_collector,
            patch(
                "argus.cli.collect_crowdsec_evidence",
                return_value=crowdsec_evidence,
            ) as crowdsec_collector,
            patch("argus.cli.render_brief", return_value="existing brief") as renderer,
        ):
            result = CliRunner().invoke(app, ["brief"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output, "existing brief\n")
        docker_collector.assert_called_once_with()
        crowdsec_collector.assert_called_once_with()
        renderer.assert_called_once_with(
            docker_evidence,
            version="0.2.0",
        )

    def test_brief_uses_release_version_in_runtime_output(self) -> None:
        with (
            patch("argus.cli.collect_docker_evidence", return_value=[]),
            patch("argus.cli.collect_crowdsec_evidence", return_value=[]),
        ):
            result = CliRunner().invoke(app, ["brief"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(result.output.startswith("ARGUS v0.2\n"), result.output)


if __name__ == "__main__":
    unittest.main()
