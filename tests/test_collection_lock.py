"""Collection overlap protection without live telemetry or systemd."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from argus.cli import app
from argus.collection_lock import collection_lock
from argus.models import Evidence
from argus.storage import EvidenceStore


class CollectionLockTests(unittest.TestCase):
    def test_lock_rejects_overlap_and_releases_after_exit(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "argus.db"
            with collection_lock(database_path):
                self.assertTrue(database_path.with_name("argus.db.lock").is_file())
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    with collection_lock(database_path):
                        self.fail("overlapping collection acquired the lock")
            with collection_lock(database_path):
                pass

    def test_lock_releases_after_failure(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "argus.db"
            with self.assertRaisesRegex(ValueError, "collector failed"):
                with collection_lock(database_path):
                    raise ValueError("collector failed")
            with collection_lock(database_path):
                pass

    def test_lock_coordinates_separate_processes(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "argus.db"
            child_code = (
                "from pathlib import Path\n"
                "from argus.collection_lock import collection_lock\n"
                "import sys\n"
                "with collection_lock(Path(sys.argv[1])):\n"
                "    pass\n"
            )
            command = [sys.executable, "-c", child_code, str(database_path)]
            project_root = Path(__file__).resolve().parents[1]
            with collection_lock(database_path):
                overlapping = subprocess.run(
                    command, cwd=project_root, capture_output=True, text=True, timeout=10
                )
            following = subprocess.run(
                command, cwd=project_root, capture_output=True, text=True, timeout=10
            )

            self.assertNotEqual(overlapping.returncode, 0)
            self.assertIn("already running", overlapping.stderr)
            self.assertEqual(following.returncode, 0, following.stderr)

    def test_overlapping_cli_collection_fails_before_collectors_or_storage(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "argus.db"
            with (
                collection_lock(database_path),
                patch("argus.cli.default_database_path", return_value=database_path),
                patch("argus.cli.collect_docker_evidence") as docker,
                patch("argus.cli.collect_crowdsec_evidence") as crowdsec,
                patch("argus.cli.collect_linux_auth_evidence") as linux_auth,
            ):
                result = CliRunner().invoke(app, ["collect"])

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("another Argus collection is already running", result.stderr)
            self.assertNotIn("ARGUS COLLECTION COMPLETE", result.output)
            self.assertFalse(database_path.exists())
            docker.assert_not_called()
            crowdsec.assert_not_called()
            linux_auth.assert_not_called()

    def test_successful_collection_still_stores_one_snapshot(self) -> None:
        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "argus.db"
            record = Evidence("docker.installed", "true")
            with (
                patch("argus.cli.default_database_path", return_value=database_path),
                patch("argus.cli.collect_docker_evidence", return_value=[record]),
                patch("argus.cli.collect_crowdsec_evidence", return_value=[]),
                patch("argus.cli.collect_linux_auth_evidence", return_value=[]),
            ):
                result = CliRunner().invoke(app, ["collect"])

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("ARGUS COLLECTION COMPLETE", result.output)
            store = EvidenceStore(database_path)
            self.assertEqual(len(store.list_collections()), 1)
            self.assertEqual(store.list_collection_evidence(1), (record,))


if __name__ == "__main__":
    unittest.main()
