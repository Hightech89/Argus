"""Offline historical summary command tests."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from argus.cli import app
from argus.models import Evidence
from argus.storage import EvidenceStore

NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)


def linux(kind: str, *, cursor: str | None = None, at: datetime = NOW, observed: bool = False, ip: str = "192.0.2.1") -> Evidence:
    message = {
        "failed": f"Failed password for alice from {ip} port 22",
        "success": f"Accepted password for alice from {ip} port 22",
        "invalid": f"Invalid user alice from {ip} port 22",
    }[kind]
    payload: dict[str, object] = {"MESSAGE": message}
    if cursor is not None:
        payload["__CURSOR"] = cursor
    if not observed:
        payload["__REALTIME_TIMESTAMP"] = str(int(at.timestamp() * 1_000_000))
    return Evidence("linux.auth.raw", json.dumps(payload), at)


def crowdsec(alert_id: int | None, *, at: datetime = NOW, ip: str = "192.0.2.1", observed: bool = False) -> Evidence:
    payload: dict[str, object] = {"message": "CrowdSec detection", "scenario": "ssh-bf", "source": {"scope": "Ip", "value": ip}}
    if alert_id is not None:
        payload["id"] = alert_id
    if not observed:
        payload["created_at"] = at.isoformat()
    return Evidence("crowdsec.alert.raw", json.dumps(payload), at)


class SummaryCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "argus.db"
        self.store = EvidenceStore(self.path)
        self.runner = CliRunner()

    def save(self, records: list[Evidence], *, collected_at: datetime = NOW) -> int:
        if not self.path.exists():
            self.store.initialize()
        return self.store.add_collection(records, collected_at=collected_at)

    def invoke(self, *args: str):
        with (
            patch("argus.cli.default_database_path", return_value=self.path),
            patch("argus.cli._utc_now", return_value=NOW) as clock,
            patch("argus.cli.collect_docker_evidence") as docker,
            patch("argus.cli.collect_crowdsec_evidence") as crowdsec_collector,
            patch("argus.cli.collect_linux_auth_evidence") as linux_collector,
        ):
            result = self.runner.invoke(app, ["summary", *args])
        self.clock_calls = clock.call_count
        docker.assert_not_called()
        crowdsec_collector.assert_not_called()
        linux_collector.assert_not_called()
        return result

    def test_command_registration_and_missing_database(self) -> None:
        self.assertIn("summary", self.runner.invoke(app, ["--help"]).output)
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ARGUS SECURITY SUMMARY", result.output)
        self.assertIn("No stored collections found.", result.output)
        self.assertIn("Total deduplicated security events: 0", result.output)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.clock_calls, 1)

    def test_collections_without_events_are_distinguished(self) -> None:
        self.save([Evidence("docker.installed", "true")])
        result = self.invoke()
        self.assertIn("Runs in window: 1", result.output)
        self.assertIn("No matching security events in the selected window.", result.output)
        self.assertNotIn("No stored collections found.", result.output)

    def test_older_collections_outside_window_are_reported_distinctly(self) -> None:
        self.save([Evidence("docker.installed", "true")], collected_at=NOW - timedelta(days=2))
        result = self.invoke()
        self.assertIn("Runs in window: 0", result.output)
        self.assertIn("Stored collections exist, but none fall within the selected window.", result.output)

    def test_default_and_custom_windows_and_all_history(self) -> None:
        self.save([
            crowdsec(1, at=NOW - timedelta(hours=23)),
            crowdsec(2, at=NOW - timedelta(hours=47)),
            crowdsec(3, at=NOW - timedelta(hours=167)),
            crowdsec(4, at=NOW - timedelta(hours=169)),
        ], collected_at=NOW - timedelta(hours=170))
        for args, count in (((), 1), (("--hours", "48"), 2), (("--hours", "168"), 3), (("--all",), 4)):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertIn(f"Total deduplicated security events: {count}", result.output)
                self.assertEqual(self.clock_calls, 1)
        self.assertIn("Investigation window: All stored history", result.output)
        self.assertIn("Runs in window: 1", result.output)

    def test_invalid_options_rejected_before_clock_or_database(self) -> None:
        for args in (("--hours", "0"), ("--hours", "abc"), ("--hours", "-1"), ("--hours", "24", "--all")):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertNotEqual(result.exit_code, 0)
                self.assertEqual(self.clock_calls, 0)
                self.assertFalse(self.path.exists())

    def test_dedup_counts_and_evidence_attribution(self) -> None:
        first = self.save([
            linux("failed", cursor="cursor-1", at=NOW - timedelta(minutes=14)),
            crowdsec(12, at=NOW - timedelta(minutes=10)),
        ])
        self.save([
            linux("failed", cursor="cursor-1", at=NOW - timedelta(minutes=14)),
            crowdsec(12, at=NOW - timedelta(minutes=10)),
            linux("success", cursor="cursor-2", at=NOW),
        ])
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Total deduplicated security events: 3", result.output)
        self.assertIn("Failed SSH authentications: 1", result.output)
        self.assertIn("Successful SSH authentications: 1", result.output)
        self.assertIn("CrowdSec alerts: 1", result.output)
        self.assertIn("CrowdSec 1", result.output)
        self.assertIn("identity crowdsec:alert:12", result.output)
        self.assertIn(f"Collection {first}", result.output)
        self.assertIn("not a confirmed compromise", result.output)

    def test_observed_timestamps_and_collection_coverage(self) -> None:
        observed_at = NOW - timedelta(hours=1)
        self.save([linux("invalid", at=observed_at, observed=True)], collected_at=NOW - timedelta(hours=2))
        result = self.invoke()
        self.assertIn("SOURCE occurrence timestamps: 0", result.output)
        self.assertIn("OBSERVED observation timestamps (occurrence unknown): 1", result.output)
        self.assertIn("Invalid SSH usernames: 1", result.output)
        self.assertIn("Runs in window: 1", result.output)
        self.assertIn((NOW - timedelta(hours=2)).isoformat(), result.output)

    def test_unkeyed_detection_uses_collection_reference_without_invented_identity(self) -> None:
        collection_id = self.save([crowdsec(None, observed=True)])
        result = self.invoke()
        self.assertIn(f"Evidence: Collection {collection_id}, OBSERVED observation", result.output)
        self.assertNotIn("identity crowdsec:alert:", result.output)
        self.assertIn("scenario ssh-bf", result.output)

    def test_read_only_and_no_limit_of_one_hundred(self) -> None:
        self.save([crowdsec(alert_id) for alert_id in range(101)])
        before = self.path.read_bytes()
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Total deduplicated security events: 101", result.output)
        self.assertEqual(self.path.read_bytes(), before)

    def test_storage_error_is_nonzero_without_traceback(self) -> None:
        self.path.touch()
        result = self.invoke()
        self.assertEqual(result.exit_code, 1)
        self.assertIn("ARGUS SUMMARY FAILED", result.stderr)
        self.assertNotIn("Traceback", result.output)


if __name__ == "__main__":
    unittest.main()
