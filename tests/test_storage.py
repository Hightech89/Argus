"""SQLite Evidence storage tests."""

from __future__ import annotations

import os
import sqlite3
import unittest
from collections.abc import Iterator
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from argus.models import Evidence
from argus.storage import EvidenceStore, default_database_path

_UTC_TIME = datetime(2026, 10, 5, 14, 30, tzinfo=timezone.utc)


class DefaultDatabasePathTests(unittest.TestCase):
    def test_default_path_uses_home_directory(self) -> None:
        with TemporaryDirectory() as home_directory:
            with patch.dict(
                os.environ,
                {"HOME": home_directory, "USERPROFILE": home_directory},
                clear=False,
            ):
                os.environ.pop("ARGUS_DB_PATH", None)

                path = default_database_path()

        self.assertEqual(path, Path(home_directory) / ".argus" / "argus.db")
        self.assertIsInstance(path, Path)

    def test_environment_variable_overrides_default(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            override = Path(temporary_directory) / "custom" / "evidence.db"
            with patch.dict(
                os.environ,
                {"ARGUS_DB_PATH": str(override)},
                clear=False,
            ):
                path = default_database_path()

            self.assertEqual(path, override)
            self.assertFalse(override.exists())

    def test_empty_environment_variable_uses_default(self) -> None:
        with TemporaryDirectory() as home_directory:
            with (
                patch.dict(os.environ, {"ARGUS_DB_PATH": ""}, clear=False),
                patch("argus.storage.Path.home", return_value=Path(home_directory)),
            ):
                path = default_database_path()

        self.assertEqual(path, Path(home_directory) / ".argus" / "argus.db")

    def test_whitespace_only_environment_variable_uses_default(self) -> None:
        with TemporaryDirectory() as home_directory:
            with (
                patch.dict(os.environ, {"ARGUS_DB_PATH": "  \t "}, clear=False),
                patch("argus.storage.Path.home", return_value=Path(home_directory)),
            ):
                path = default_database_path()

        self.assertEqual(path, Path(home_directory) / ".argus" / "argus.db")

    def test_environment_path_expands_home_directory(self) -> None:
        with TemporaryDirectory() as home_directory:
            with patch.dict(
                os.environ,
                {
                    "ARGUS_DB_PATH": "~/custom/argus.db",
                    "HOME": home_directory,
                    "USERPROFILE": home_directory,
                },
                clear=False,
            ):
                path = default_database_path()

        self.assertEqual(path, Path(home_directory) / "custom" / "argus.db")

    def test_relative_override_uses_platform_path_semantics(self) -> None:
        with patch.dict(
            os.environ,
            {"ARGUS_DB_PATH": "relative/nested/argus.db"},
            clear=False,
        ):
            path = default_database_path()

        self.assertEqual(path, Path("relative") / "nested" / "argus.db")
        self.assertIsInstance(path, Path)


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.path = Path(self.temporary_directory.name) / "argus.db"
        self.store = EvidenceStore(self.path)

    def test_initialize_creates_database_and_schema(self) -> None:
        self.assertFalse(self.path.exists())

        self.store.initialize()

        self.assertTrue(self.path.is_file())
        with closing(sqlite3.connect(self.path)) as connection:
            columns = connection.execute("PRAGMA table_info(evidence)").fetchall()
        self.assertEqual(
            [(column[1], column[2], column[3], column[5]) for column in columns],
            [
                ("id", "INTEGER", 0, 1),
                ("source", "TEXT", 1, 0),
                ("content", "TEXT", 1, 0),
                ("observed_at", "TEXT", 0, 0),
            ],
        )

    def test_operations_require_initialization_without_creating_database(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "must be initialized"):
            self.store.list_evidence()

        self.assertFalse(self.path.exists())

    def test_initialize_is_idempotent_and_preserves_records(self) -> None:
        self.store.initialize()
        record = Evidence("crowdsec.alert.raw", "exact content", _UTC_TIME)
        self.store.add(record)

        self.store.initialize()
        self.store.initialize()

        self.assertEqual(self.store.list_evidence(), (record,))

    def test_one_evidence_record_round_trips_exactly(self) -> None:
        self.store.initialize()
        record = Evidence(
            "source.with punctuation",
            "line one\nline two 'quoted' \x00 exact",
            _UTC_TIME,
        )

        inserted_id = self.store.add(record)

        self.assertEqual(inserted_id, 1)
        self.assertEqual(self.store.list_evidence(), (record,))

    def test_multiple_records_preserve_insertion_order_and_return_ids(self) -> None:
        self.store.initialize()
        records = (
            Evidence("second-by-name", "first row", _UTC_TIME),
            Evidence("first-by-name", "second row", None),
            Evidence("second-by-name", "third row", _UTC_TIME),
        )

        inserted_ids = self.store.add_many(iter(records))

        self.assertEqual(inserted_ids, (1, 2, 3))
        self.assertEqual(self.store.list_evidence(), records)

    def test_non_utc_offset_round_trips_without_normalization(self) -> None:
        self.store.initialize()
        offset = timezone(timedelta(hours=-5, minutes=-30))
        observed_at = datetime(2026, 10, 5, 9, 0, tzinfo=offset)
        record = Evidence("crowdsec.alert.raw", "{}", observed_at)

        self.store.add(record)
        restored = self.store.list_evidence()[0]

        self.assertEqual(restored.observed_at, observed_at)
        self.assertEqual(restored.observed_at.utcoffset(), offset.utcoffset(None))

    def test_none_observed_at_round_trips_as_none(self) -> None:
        self.store.initialize()
        record = Evidence("manual.note", "no observation time", None)

        self.store.add(record)

        self.assertIsNone(self.store.list_evidence()[0].observed_at)

    def test_duplicate_evidence_records_are_allowed(self) -> None:
        self.store.initialize()
        record = Evidence("crowdsec.alert.raw", '{"id":42}', _UTC_TIME)

        inserted_ids = self.store.add_many((record, record))

        self.assertEqual(inserted_ids, (1, 2))
        self.assertEqual(self.store.list_evidence(), (record, record))

    def test_add_many_rolls_back_the_entire_failed_batch(self) -> None:
        self.store.initialize()
        existing = Evidence("existing", "before batch", _UTC_TIME)
        self.store.add(existing)
        valid = Evidence("valid", "would be inserted first", _UTC_TIME)
        invalid = Evidence(None, "violates NOT NULL", _UTC_TIME)  # type: ignore[arg-type]

        with self.assertRaises(sqlite3.IntegrityError):
            self.store.add_many((valid, invalid))

        self.assertEqual(self.store.list_evidence(), (existing,))

    def test_batch_iterator_failure_rolls_back_inserted_rows(self) -> None:
        self.store.initialize()

        def failing_batch() -> Iterator[Evidence]:
            yield Evidence("first", "not committed", _UTC_TIME)
            raise RuntimeError("fixture failure")

        with self.assertRaisesRegex(RuntimeError, "fixture failure"):
            self.store.add_many(failing_batch())

        self.assertEqual(self.store.list_evidence(), ())

    def test_separate_temporary_databases_are_independent(self) -> None:
        self.store.initialize()
        self.store.add(Evidence("first", "database one", _UTC_TIME))

        with TemporaryDirectory() as other_directory:
            other_store = EvidenceStore(Path(other_directory) / "argus.db")
            other_store.initialize()
            other_store.add(Evidence("second", "database two", None))

            self.assertEqual(
                [record.source for record in self.store.list_evidence()], ["first"]
            )
            self.assertEqual(
                [record.source for record in other_store.list_evidence()], ["second"]
            )

    def test_list_evidence_returns_an_immutable_tuple(self) -> None:
        self.store.initialize()
        self.store.add(Evidence("source", "content", _UTC_TIME))

        records = self.store.list_evidence()

        self.assertIsInstance(records, tuple)
        with self.assertRaises(TypeError):
            records[0] = Evidence("changed", "changed")


if __name__ == "__main__":
    unittest.main()
