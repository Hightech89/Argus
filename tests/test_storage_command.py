"""Read-only storage reporting with temporary databases and mocked disk space."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from typer.testing import CliRunner

from argus.cli import LOW_SPACE_WARNING_BYTES, app
from argus.models import Evidence
from argus.storage import EvidenceStore

NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


class StorageCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "nested" / "argus.db"
        self.runner = CliRunner()

    def invoke(self, free_bytes: int = LOW_SPACE_WARNING_BYTES):
        with (
            patch("argus.cli.default_database_path", return_value=self.path),
            patch("argus.cli.shutil.disk_usage", return_value=SimpleNamespace(free=free_bytes)),
            patch("argus.cli.collect_docker_evidence") as docker,
            patch("argus.cli.collect_crowdsec_evidence") as crowdsec,
            patch("argus.cli.collect_linux_auth_evidence") as linux,
        ):
            result = self.runner.invoke(app, ["storage"])
        docker.assert_not_called()
        crowdsec.assert_not_called()
        linux.assert_not_called()
        return result

    def test_registration_and_missing_database_do_not_create_directories(self) -> None:
        self.assertIn("storage", self.runner.invoke(app, ["--help"]).output)
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(f"Database: {self.path}", result.output)
        self.assertIn("Database file size: 0 bytes", result.output)
        self.assertIn("Collection runs: 0", result.output)
        self.assertIn("Evidence records: 0", result.output)
        self.assertIn("No database found", result.output)
        self.assertFalse(self.path.parent.exists())

    def test_empty_database_and_zero_byte_file(self) -> None:
        self.path.parent.mkdir()
        self.path.touch()
        self.assertIn("Evidence records: 0", self.invoke().output)
        EvidenceStore(self.path).initialize()
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Collection runs: 0", result.output)
        self.assertNotIn("No database found", result.output)

    def test_counts_sizes_auxiliary_files_and_read_only_behavior(self) -> None:
        self.path.parent.mkdir()
        store = EvidenceStore(self.path)
        store.initialize()
        store.add_collection(
            [Evidence("docker.installed", "true"), Evidence("linux.auth.raw", "{}")],
            collected_at=NOW,
        )
        store.add(Evidence("docker.installed", "false"))
        auxiliary = Path(f"{self.path}-shm")
        auxiliary.write_bytes(b"transient")
        before = self.path.read_bytes()

        result = self.invoke()

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(f"Database file size: {len(before)} bytes", result.output)
        self.assertIn("SQLite auxiliary files: 9 bytes", result.output)
        self.assertIn(f"Total SQLite files: {len(before) + 9} bytes", result.output)
        self.assertIn("Collection runs: 1", result.output)
        self.assertIn("Evidence records: 3", result.output)
        self.assertIn("docker.installed: 2", result.output)
        self.assertIn("linux.auth.raw: 1", result.output)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(auxiliary.read_bytes(), b"transient")

    def test_low_space_warning_threshold(self) -> None:
        normal = self.invoke(LOW_SPACE_WARNING_BYTES)
        low = self.invoke(LOW_SPACE_WARNING_BYTES - 1)
        self.assertNotIn("WARNING", normal.output)
        self.assertIn("WARNING: available disk space is below 1 GiB.", low.output)

    def test_storage_failure_is_concise_and_nonzero(self) -> None:
        self.path.parent.mkdir()
        self.path.write_bytes(b"not SQLite")
        result = self.invoke()
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("ARGUS STORAGE FAILED", result.stderr)
        self.assertNotIn("Traceback", result.output)


if __name__ == "__main__":
    unittest.main()
