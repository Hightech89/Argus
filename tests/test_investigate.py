"""Historical investigation reads only stored Evidence."""

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

_NOW = datetime(2026, 10, 7, 18, 30, tzinfo=timezone.utc)


def _crowdsec(
    alert_id: object = None,
    *,
    message: str = "CrowdSec alert",
    occurred_at: datetime | None = None,
    observed_at: datetime = _NOW,
) -> Evidence:
    payload: dict[str, object] = {"message": message}
    if alert_id is not None:
        payload["id"] = alert_id
    if occurred_at is not None:
        payload["created_at"] = occurred_at.isoformat()
    return Evidence("crowdsec.alert.raw", json.dumps(payload), observed_at)


def _linux(
    message: str = "Invalid user alice from 192.0.2.1 port 22",
    *,
    cursor: str | None = None,
    occurred_at: datetime | None = None,
    observed_at: datetime = _NOW,
) -> Evidence:
    payload: dict[str, object] = {"MESSAGE": message}
    if cursor is not None:
        payload["__CURSOR"] = cursor
    if occurred_at is not None:
        payload["__REALTIME_TIMESTAMP"] = str(
            int(occurred_at.timestamp()) * 1_000_000 + occurred_at.microsecond
        )
    return Evidence("linux.auth.raw", json.dumps(payload), observed_at)


class InvestigationCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "argus.db"
        self.store = EvidenceStore(self.path)
        self.runner = CliRunner()

    def _save(self, evidence: list[Evidence], *, at: datetime = _NOW) -> int:
        if not self.path.exists():
            self.store.initialize()
        return self.store.add_collection(evidence, collected_at=at)

    def _invoke(self, *arguments: str):
        with (
            patch("argus.cli.default_database_path", return_value=self.path),
            patch("argus.cli.collect_crowdsec_evidence") as crowdsec,
            patch("argus.cli.collect_linux_auth_evidence") as linux,
            patch("argus.cli.collect_docker_evidence") as docker,
        ):
            result = self.runner.invoke(app, ["investigate", *arguments])
        crowdsec.assert_not_called()
        linux.assert_not_called()
        docker.assert_not_called()
        return result

    def test_command_registration(self) -> None:
        result = self.runner.invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("investigate", result.output)

    def test_missing_database_is_empty_without_creating_it(self) -> None:
        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ARGUS INVESTIGATION", result.output)
        self.assertIn("No stored security events found.", result.output)
        self.assertFalse(self.path.exists())

    def test_empty_database_and_empty_collection_are_graceful(self) -> None:
        self.store.initialize()
        self.assertIn("No stored security events found.", self._invoke().output)
        self._save([Evidence("docker.installed", "true")])

        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No stored security events found.", result.output)

    def test_crowdsec_event_shows_source_time_details_and_collection(self) -> None:
        occurred = _NOW - timedelta(hours=1)
        collection_id = self._save(
            [_crowdsec(12, message="SSH intrusion detected", occurred_at=occurred)]
        )

        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(occurred.isoformat(), result.output)
        self.assertIn("SOURCE (occurrence time) | crowdsec | medium", result.output)
        self.assertIn("SSH intrusion detected", result.output)
        self.assertIn("Alert ID: 12", result.output)
        self.assertIn(f"Collection: {collection_id}", result.output)

    def test_linux_auth_events_show_observed_and_source_timestamps(self) -> None:
        occurred = _NOW - timedelta(minutes=20)
        collection_id = self._save(
            [
                _linux(observed_at=_NOW - timedelta(minutes=10)),
                _linux(
                    "Accepted publickey for bob from 192.0.2.2 port 22",
                    occurred_at=occurred,
                ),
            ]
        )

        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(
            "OBSERVED (observation time; occurrence unknown) | linux-auth | low",
            result.output,
        )
        self.assertIn("SOURCE (occurrence time) | linux-auth | info", result.output)
        self.assertIn("SSH invalid user", result.output)
        self.assertIn("SSH login accepted", result.output)
        self.assertIn("Username: bob", result.output)
        self.assertIn("Remote IP: 192.0.2.2", result.output)
        self.assertIn("Auth Method: publickey", result.output)
        self.assertEqual(result.output.count(f"Collection: {collection_id}"), 2)

    def test_mixed_sources_sort_newest_first_with_stable_timestamp_ties(self) -> None:
        self._save(
            [
                _crowdsec(message="CrowdSec tie", occurred_at=_NOW),
                _linux("Invalid user tie from 192.0.2.1", occurred_at=_NOW),
                _crowdsec(message="Older event", occurred_at=_NOW - timedelta(hours=1)),
            ]
        )

        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertLess(result.output.index("CrowdSec tie"), result.output.index("SSH invalid user"))
        self.assertLess(result.output.index("SSH invalid user"), result.output.index("Older event"))

    def test_timestamp_ties_across_collections_keep_collection_order(self) -> None:
        first = self._save([_crowdsec(1, message="First tied", occurred_at=_NOW)])
        second = self._save(
            [_crowdsec(2, message="Second tied", occurred_at=_NOW)],
            at=_NOW + timedelta(hours=1),
        )

        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertLess(result.output.index("First tied"), result.output.index("Second tied"))
        self.assertIn(f"Collection: {first}", result.output)
        self.assertIn(f"Collection: {second}", result.output)

    def test_source_filtering_happens_before_deduplication(self) -> None:
        self._save([_crowdsec(12), _linux(cursor="cursor-a")])

        crowdsec = self._invoke("--source", "crowdsec")
        linux = self._invoke("--source", "linux-auth")

        self.assertEqual(crowdsec.exit_code, 0, crowdsec.output)
        self.assertIn("CrowdSec alert", crowdsec.output)
        self.assertNotIn("SSH invalid user", crowdsec.output)
        self.assertEqual(linux.exit_code, 0, linux.output)
        self.assertIn("SSH invalid user", linux.output)
        self.assertNotIn("CrowdSec alert", linux.output)

    def test_repeated_identity_uses_earliest_stored_collection(self) -> None:
        first = self._save(
            [_crowdsec(12, message="First stored", occurred_at=_NOW)]
        )
        second = self._save(
            [_crowdsec(12, message="Later stored", occurred_at=_NOW + timedelta(hours=1))],
            at=_NOW + timedelta(hours=2),
        )

        result = self._invoke()

        self.assertIn("First stored", result.output)
        self.assertNotIn("Later stored", result.output)
        self.assertIn(f"Collection: {first}", result.output)
        self.assertNotIn(f"Collection: {second}", result.output)
        self.assertIn("earliest stored collection", result.output)

    def test_linux_cursor_deduplicates_across_collections(self) -> None:
        first = self._save([_linux(cursor="cursor-a")])
        self._save([_linux(cursor="cursor-a")], at=_NOW + timedelta(hours=1))

        result = self._invoke()

        self.assertEqual(result.output.count("SSH invalid user"), 1)
        self.assertIn(f"Collection: {first}", result.output)

    def test_unkeyed_events_are_all_retained(self) -> None:
        first = self._save([_crowdsec(message="Unkeyed repeated")])
        second = self._save(
            [_crowdsec(message="Unkeyed repeated")], at=_NOW + timedelta(hours=1)
        )

        result = self._invoke()

        self.assertEqual(result.output.count("Unkeyed repeated"), 2)
        self.assertIn(f"Collection: {first}", result.output)
        self.assertIn(f"Collection: {second}", result.output)

    def test_limit_applies_after_deduplication_and_sorting(self) -> None:
        self._save(
            [
                _crowdsec(1, message="Old keyed", occurred_at=_NOW - timedelta(hours=2)),
                _crowdsec(2, message="Middle", occurred_at=_NOW - timedelta(hours=1)),
            ]
        )
        self._save(
            [_crowdsec(1, message="New duplicate", occurred_at=_NOW)],
            at=_NOW + timedelta(hours=1),
        )

        result = self._invoke("--limit", "1")

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Middle", result.output)
        self.assertNotIn("Old keyed", result.output)
        self.assertNotIn("New duplicate", result.output)
        self.assertEqual(result.output.count("  Collection: "), 1)

    def test_default_limit_is_twenty_events(self) -> None:
        self._save([_crowdsec(alert_id, message=f"Alert {alert_id}") for alert_id in range(22)])

        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.count("  Collection: "), 20)

    def test_invalid_limit_and_source_are_rejected_before_storage(self) -> None:
        for args in (("--limit", "0"), ("--source", "docker")):
            with self.subTest(args=args):
                result = self._invoke(*args)
                self.assertNotEqual(result.exit_code, 0)
                self.assertIn("Invalid value", result.output)

    def test_malformed_evidence_is_skipped(self) -> None:
        self._save(
            [
                Evidence("crowdsec.alert.raw", "{broken", _NOW),
                Evidence("linux.auth.raw", "[]", _NOW),
                Evidence("linux.auth.raw", '{"MESSAGE":"session opened"}', _NOW),
                _linux("Accepted password for alice from 192.0.2.1 port 22"),
            ]
        )

        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.count("  Collection: "), 1)
        self.assertIn("SSH login accepted", result.output)

    def test_investigation_does_not_modify_database(self) -> None:
        collection_id = self._save([_crowdsec(12)])
        before = self.path.read_bytes()

        result = self._invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.store.list_collection_evidence(collection_id), (_crowdsec(12),))

    def test_storage_error_exits_nonzero_without_traceback(self) -> None:
        self.path.touch()

        result = self._invoke()

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("ARGUS INVESTIGATION FAILED", result.stderr)
        self.assertNotIn("Traceback", result.output)


if __name__ == "__main__":
    unittest.main()
