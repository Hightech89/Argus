"""Command-line interface tests."""

from __future__ import annotations

import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from argus.cli import _utc_now, app
from argus.models import Evidence
from argus.storage import EvidenceStore

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
    def test_daily_combines_crowdsec_then_linux_auth_after_both_collections(self) -> None:
        crowdsec = _raw_alert("CrowdSec first", observed_at=_NOW - timedelta(minutes=2))
        linux = Evidence(
            "linux.auth.raw",
            json.dumps({"MESSAGE": "Invalid user alice from 192.0.2.1"}),
            _NOW - timedelta(minutes=1),
        )
        order: list[str] = []

        def collect_crowdsec() -> list[Evidence]:
            order.append("crowdsec")
            return [crowdsec]

        def collect_linux() -> list[Evidence]:
            order.append("linux-auth")
            return [linux]

        def clock() -> datetime:
            order.append("clock")
            return _NOW

        with (
            patch("argus.cli.collect_crowdsec_evidence", side_effect=collect_crowdsec),
            patch("argus.cli.collect_linux_auth_evidence", side_effect=collect_linux),
            patch("argus.cli._utc_now", side_effect=clock) as clock_mock,
        ):
            result = self.runner.invoke(app, ["daily"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(order, ["crowdsec", "linux-auth", "clock"])
        clock_mock.assert_called_once_with()
        self.assertIn("Observed - Event Time Unknown\nTotal: 2", result.output)
        self.assertLess(result.output.index("CrowdSec first"), result.output.index("SSH invalid user"))
        self.assertIn("Event Type: ssh_invalid_user", result.output)
        self.assertIn("Username: alice", result.output)
        self.assertIn("Remote IP: 192.0.2.1", result.output)

    def test_daily_keeps_repeated_authoritatively_identified_observations(self) -> None:
        record = Evidence(
            "crowdsec.alert.raw",
            json.dumps({"id": 12, "message": "Repeated alert"}),
            _NOW,
        )

        result = self._invoke_daily([record, record])

        self.assertIn("Observed - Event Time Unknown\nTotal: 2", result.output)
        self.assertEqual(result.output.count("Repeated alert"), 2)

    def setUp(self) -> None:
        self.runner = CliRunner()
        linux_collector = patch("argus.cli.collect_linux_auth_evidence", return_value=[])
        self.linux_collector = linux_collector.start()
        self.addCleanup(linux_collector.stop)

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

    def test_daily_remains_read_only(self) -> None:
        with (
            patch("argus.cli.EvidenceStore") as store,
            patch("argus.cli._utc_now", return_value=_NOW),
            patch("argus.cli.collect_crowdsec_evidence", return_value=[]),
        ):
            result = self.runner.invoke(app, ["daily"])

        self.assertEqual(result.exit_code, 0, result.output)
        store.assert_not_called()


class CollectCommandTests(unittest.TestCase):
    def test_collect_stores_linux_auth_after_docker_and_crowdsec(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            docker = Evidence("docker.installed", "true", _NOW)
            crowdsec = Evidence("crowdsec.available", "true", _NOW)
            linux = Evidence("linux.auth.raw", '{"MESSAGE":"Invalid user a from 192.0.2.1"}', _NOW)
            with (
                patch("argus.cli.default_database_path", return_value=database_path),
                patch("argus.cli._utc_now", return_value=_NOW),
                patch("argus.cli.collect_docker_evidence", return_value=[docker]),
                patch("argus.cli.collect_crowdsec_evidence", return_value=[crowdsec]),
                patch("argus.cli.collect_linux_auth_evidence", return_value=[linux]) as linux_collector,
            ):
                result = self.runner.invoke(app, ["collect"])

            self.assertEqual(result.exit_code, 0, result.output)
            linux_collector.assert_called_once_with()
            self.assertIn("Evidence stored: 3", result.output)
            self.assertIn("Linux auth records: 1", result.output)
            store = EvidenceStore(database_path)
            self.assertEqual(store.list_collection_evidence(1), (docker, crowdsec, linux))
            self.assertEqual(len(store.list_collections()), 1)

    def test_collect_persists_linux_operational_error_evidence(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            linux_error = Evidence("linux.auth.error", "journalctl unavailable", _NOW)
            with (
                patch("argus.cli.default_database_path", return_value=database_path),
                patch("argus.cli._utc_now", return_value=_NOW),
                patch("argus.cli.collect_docker_evidence", return_value=[]),
                patch("argus.cli.collect_crowdsec_evidence", return_value=[]),
                patch("argus.cli.collect_linux_auth_evidence", return_value=[linux_error]),
            ):
                result = self.runner.invoke(app, ["collect"])

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Linux auth records: 1", result.output)
            self.assertEqual(
                EvidenceStore(database_path).list_collection_evidence(1), (linux_error,)
            )

    def setUp(self) -> None:
        self.runner = CliRunner()
        linux_collector = patch("argus.cli.collect_linux_auth_evidence", return_value=[])
        self.linux_collector = linux_collector.start()
        self.addCleanup(linux_collector.stop)

    def test_collect_command_is_registered(self) -> None:
        result = self.runner.invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("collect", result.output)

    def test_collect_uses_default_path_and_one_ordered_snapshot_call(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "data" / "argus.db"
            docker = [Evidence("docker.first", "1"), Evidence("docker.second", "2")]
            crowdsec = [Evidence("crowdsec.first", "3")]
            store = MagicMock()
            store.add_collection.return_value = 12
            call_order: list[str] = []
            store.initialize.side_effect = lambda: call_order.append("initialize")

            def clock() -> datetime:
                call_order.append("clock")
                return _NOW

            def collect_docker() -> list[Evidence]:
                call_order.append("docker")
                return docker

            def collect_crowdsec() -> list[Evidence]:
                call_order.append("crowdsec")
                return crowdsec

            with (
                patch("argus.cli.default_database_path", return_value=database_path) as path,
                patch("argus.cli.EvidenceStore", return_value=store) as store_type,
                patch("argus.cli._utc_now", side_effect=clock) as clock_mock,
                patch("argus.cli.collect_docker_evidence", side_effect=collect_docker) as docker_collector,
                patch("argus.cli.collect_crowdsec_evidence", side_effect=collect_crowdsec) as crowdsec_collector,
            ):
                result = self.runner.invoke(app, ["collect"])

        self.assertEqual(result.exit_code, 0, result.output)
        path.assert_called_once_with()
        store_type.assert_called_once_with(database_path)
        store.initialize.assert_called_once_with()
        clock_mock.assert_called_once_with()
        docker_collector.assert_called_once_with()
        crowdsec_collector.assert_called_once_with()
        self.assertEqual(call_order, ["initialize", "clock", "docker", "crowdsec"])
        store.add_collection.assert_called_once_with(
            [*docker, *crowdsec], collected_at=_NOW
        )
        self.assertIn("ARGUS COLLECTION COMPLETE", result.output)
        self.assertIn("Collection: 12", result.output)
        self.assertIn("Evidence stored: 3", result.output)
        self.assertIn("Docker records: 2", result.output)
        self.assertIn("CrowdSec records: 1", result.output)
        self.assertIn(f"Database: {database_path}", result.output)

    def test_argus_db_path_creates_parent_and_persists_readable_evidence(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "nested" / "argus.db"
            docker = [Evidence("docker.record", "docker", _NOW)]
            crowdsec = [Evidence("crowdsec.record", "crowdsec", _NOW)]
            with (
                patch.dict(os.environ, {"ARGUS_DB_PATH": str(database_path)}),
                patch("argus.cli._utc_now", return_value=_NOW),
                patch("argus.cli.collect_docker_evidence", return_value=docker),
                patch("argus.cli.collect_crowdsec_evidence", return_value=crowdsec),
            ):
                result = self.runner.invoke(app, ["collect"])

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(database_path.parent.is_dir())
            self.assertTrue(database_path.is_file())
            self.assertIn(f"Database: {database_path}", result.output)
            store = EvidenceStore(database_path)
            self.assertEqual(store.list_collection_evidence(1), (*docker, *crowdsec))

    def test_collector_error_evidence_is_persisted(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            docker_error = Evidence("docker.error", "Docker CLI not found.", _NOW)
            crowdsec_error = Evidence("crowdsec.error", "Docker unavailable.", _NOW)
            with (
                patch("argus.cli.default_database_path", return_value=database_path),
                patch("argus.cli._utc_now", return_value=_NOW),
                patch("argus.cli.collect_docker_evidence", return_value=[docker_error]),
                patch("argus.cli.collect_crowdsec_evidence", return_value=[crowdsec_error]),
            ):
                result = self.runner.invoke(app, ["collect"])

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(
                EvidenceStore(database_path).list_collection_evidence(1),
                (docker_error, crowdsec_error),
            )

    def test_storage_failure_exits_nonzero_without_success_output(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            store = MagicMock()
            store.add_collection.side_effect = OSError("database is read-only")
            with (
                patch(
                    "argus.cli.default_database_path",
                    return_value=Path(temporary_directory) / "argus.db",
                ),
                patch("argus.cli.EvidenceStore", return_value=store),
                patch("argus.cli.collect_docker_evidence", return_value=[]),
                patch("argus.cli.collect_crowdsec_evidence", return_value=[]),
            ):
                result = self.runner.invoke(app, ["collect"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("ARGUS COLLECTION FAILED: database is read-only", result.stderr)
        self.assertNotIn("ARGUS COLLECTION COMPLETE", result.output)

    def test_initialization_failure_exits_before_collection(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            store = MagicMock()
            store.initialize.side_effect = OSError("cannot initialize database")
            with (
                patch(
                    "argus.cli.default_database_path",
                    return_value=Path(temporary_directory) / "argus.db",
                ),
                patch("argus.cli.EvidenceStore", return_value=store),
                patch("argus.cli._utc_now") as clock,
                patch("argus.cli.collect_docker_evidence") as docker_collector,
            ):
                result = self.runner.invoke(app, ["collect"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("ARGUS COLLECTION FAILED: cannot initialize database", result.stderr)
        self.assertNotIn("ARGUS COLLECTION COMPLETE", result.output)
        clock.assert_not_called()
        docker_collector.assert_not_called()

    def test_directory_creation_failure_exits_nonzero(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            with (
                patch(
                    "argus.cli.default_database_path",
                    return_value=Path(temporary_directory) / "nested" / "argus.db",
                ),
                patch("pathlib.Path.mkdir", side_effect=OSError("permission denied")),
                patch("argus.cli.collect_docker_evidence") as docker_collector,
            ):
                result = self.runner.invoke(app, ["collect"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("ARGUS COLLECTION FAILED: permission denied", result.stderr)
        self.assertNotIn("ARGUS COLLECTION COMPLETE", result.output)
        docker_collector.assert_not_called()

    def test_unexpected_collector_failure_exits_nonzero_without_success(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            with (
                patch("argus.cli.default_database_path", return_value=database_path),
                patch(
                    "argus.cli.collect_docker_evidence",
                    side_effect=RuntimeError("collector crashed"),
                ),
                patch("argus.cli.collect_crowdsec_evidence") as crowdsec_collector,
            ):
                result = self.runner.invoke(app, ["collect"])

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("ARGUS COLLECTION FAILED: collector crashed", result.stderr)
            self.assertNotIn("ARGUS COLLECTION COMPLETE", result.output)
            crowdsec_collector.assert_not_called()
            self.assertEqual(EvidenceStore(database_path).list_evidence(), ())


class HistoryCommandTests(unittest.TestCase):
    def test_history_counts_linux_auth_observations_separately(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            store = EvidenceStore(database_path)
            store.initialize()
            store.add_collection(
                [
                    Evidence("docker.installed", "true"),
                    Evidence("crowdsec.available", "true"),
                    Evidence("linux.auth.available", "true"),
                    Evidence("linux.auth.raw", "{}"),
                    Evidence("manual.note", "other"),
                ],
                collected_at=_NOW,
            )
            with patch("argus.cli.default_database_path", return_value=database_path):
                result = self.runner.invoke(app, ["history"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Evidence: 5", result.output)
        self.assertIn("Docker records: 1", result.output)
        self.assertIn("CrowdSec records: 1", result.output)
        self.assertIn("Linux auth records: 2", result.output)
        self.assertIn("Other records: 1", result.output)

    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_history_command_is_registered(self) -> None:
        result = self.runner.invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("history", result.output)

    def test_missing_database_is_an_empty_state_and_is_not_created(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "missing" / "argus.db"
            with (
                patch("argus.cli.default_database_path", return_value=database_path) as path,
                patch("argus.cli.EvidenceStore") as store_type,
            ):
                result = self.runner.invoke(app, ["history"])

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("ARGUS HISTORY", result.output)
            self.assertIn("No collection history found.", result.output)
            self.assertIn("argus collect", result.output)
            self.assertFalse(database_path.exists())
            path.assert_called_once_with()
            store_type.assert_not_called()

    def test_initialized_database_without_collections_is_an_empty_state(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            EvidenceStore(database_path).initialize()
            with patch("argus.cli.default_database_path", return_value=database_path):
                result = self.runner.invoke(app, ["history"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No collection history found.", result.output)

    def test_path_override_shows_one_collection_and_source_counts(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "history.db"
            store = EvidenceStore(database_path)
            store.initialize()
            collection_id = store.add_collection(
                [
                    Evidence("docker.first", "1"),
                    Evidence("docker.second", "2"),
                    Evidence("crowdsec.first", "3"),
                    Evidence("manual.note", "4"),
                ],
                collected_at=_NOW,
            )
            with patch.dict(os.environ, {"ARGUS_DB_PATH": str(database_path)}):
                result = self.runner.invoke(app, ["history"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(f"Collection {collection_id}", result.output)
        self.assertIn(f"Time: {_NOW.isoformat()}", result.output)
        self.assertIn("Evidence: 4", result.output)
        self.assertIn("Docker records: 2", result.output)
        self.assertIn("CrowdSec records: 1", result.output)
        self.assertIn("Other records: 1", result.output)
        self.assertIn("Stored observations grouped by collection run.", result.output)
        self.assertNotIn("attacks", result.output.lower())
        self.assertNotIn("incidents", result.output.lower())

    def test_multiple_collections_are_shown_newest_first(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            store = EvidenceStore(database_path)
            store.initialize()
            first_id = store.add_collection([], collected_at=_NOW - timedelta(hours=1))
            second_id = store.add_collection([], collected_at=_NOW)
            with patch("argus.cli.default_database_path", return_value=database_path):
                result = self.runner.invoke(app, ["history"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertLess(
            result.output.index(f"Collection {second_id}"),
            result.output.index(f"Collection {first_id}"),
        )

    def test_default_limit_shows_ten_most_recent_collections(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            self._add_collections(database_path, 12)
            with patch("argus.cli.default_database_path", return_value=database_path):
                result = self.runner.invoke(app, ["history"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.count("\nCollection "), 10)
        self.assertIn("Collection 12", result.output)
        self.assertIn("Collection 3", result.output)
        self.assertNotIn("\nCollection 2\n", result.output)

    def test_custom_limit_is_applied(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            self._add_collections(database_path, 5)
            with patch("argus.cli.default_database_path", return_value=database_path):
                result = self.runner.invoke(app, ["history", "--limit", "2"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.count("\nCollection "), 2)
        self.assertIn("Collection 5", result.output)
        self.assertIn("Collection 4", result.output)
        self.assertNotIn("\nCollection 3\n", result.output)

    def test_nonpositive_limit_is_rejected_before_storage_access(self) -> None:
        with patch("argus.cli.default_database_path") as path:
            result = self.runner.invoke(app, ["history", "--limit", "0"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid value", result.output)
        self.assertNotIn("ARGUS HISTORY\n", result.output)
        path.assert_not_called()

    def test_storage_failure_exits_nonzero_without_traceback_or_history(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            database_path.touch()
            store = MagicMock()
            store.list_collections.side_effect = OSError("cannot read database")
            with (
                patch("argus.cli.default_database_path", return_value=database_path),
                patch("argus.cli.EvidenceStore", return_value=store),
            ):
                result = self.runner.invoke(app, ["history"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("ARGUS HISTORY FAILED: cannot read database", result.stderr)
        self.assertNotIn("ARGUS HISTORY\n", result.output)
        self.assertNotIn("Traceback", result.output)
        store.initialize.assert_not_called()

    def test_history_does_not_modify_database(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "argus.db"
            store = EvidenceStore(database_path)
            store.initialize()
            run_id = store.add_collection(
                [Evidence("docker.record", "stored", _NOW)], collected_at=_NOW
            )
            before = database_path.read_bytes()
            with patch("argus.cli.default_database_path", return_value=database_path):
                result = self.runner.invoke(app, ["history"])
            after = database_path.read_bytes()

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(after, before)
            self.assertEqual(
                store.list_collection_evidence(run_id),
                (Evidence("docker.record", "stored", _NOW),),
            )

    @staticmethod
    def _add_collections(database_path: Path, count: int) -> None:
        store = EvidenceStore(database_path)
        store.initialize()
        for index in range(count):
            store.add_collection(
                [], collected_at=_NOW + timedelta(minutes=index)
            )


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

    def test_brief_remains_read_only(self) -> None:
        with (
            patch("argus.cli.EvidenceStore") as store,
            patch("argus.cli.collect_docker_evidence", return_value=[]),
            patch("argus.cli.collect_crowdsec_evidence", return_value=[]),
        ):
            result = CliRunner().invoke(app, ["brief"])

        self.assertEqual(result.exit_code, 0, result.output)
        store.assert_not_called()

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
