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

from argus.models import CollectionRun, Evidence
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
                ("collection_id", "INTEGER", 0, 0),
            ],
        )

    def test_operations_require_initialization_without_creating_database(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "must be initialized"):
            self.store.list_evidence()

        self.assertFalse(self.path.exists())

    def test_collection_runs_schema(self) -> None:
        self.store.initialize()
        with closing(sqlite3.connect(self.path)) as connection:
            columns = connection.execute("PRAGMA table_info(collection_runs)").fetchall()
            foreign_keys = connection.execute("PRAGMA foreign_key_list(evidence)").fetchall()
        self.assertEqual(
            [(column[1], column[2], column[3], column[5]) for column in columns],
            [("id", "INTEGER", 0, 1), ("collected_at", "TEXT", 1, 0)],
        )
        self.assertEqual(len(foreign_keys), 1)
        self.assertEqual(foreign_keys[0][2:5], ("collection_runs", "collection_id", "id"))

    def test_legacy_schema_upgrade_preserves_evidence_and_ids(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                "CREATE TABLE evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "source TEXT NOT NULL, content TEXT NOT NULL, observed_at TEXT NULL)"
            )
            connection.executemany(
                "INSERT INTO evidence VALUES (?, ?, ?, ?)",
                [(7, "old", "exact content", _UTC_TIME.isoformat()),
                 (9, "manual", "no time", None)],
            )
        self.store.initialize()
        self.store.initialize()
        self.assertEqual(self.store.list_evidence(), (
            Evidence("old", "exact content", _UTC_TIME),
            Evidence("manual", "no time"),
        ))
        with self.store._connection() as connection:
            self.assertEqual(connection.execute(
                "SELECT id, collection_id FROM evidence ORDER BY id"
            ).fetchall(), [(7, None), (9, None)])
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE evidence SET collection_id = 999 WHERE id = 7")
        run_id = self.store.add_collection([Evidence("new", "snapshot")], collected_at=_UTC_TIME)
        self.assertEqual(self.store.list_collection_evidence(run_id), (Evidence("new", "snapshot"),))
        self.assertEqual(self.store.add(Evidence("next", "standalone")), 11)

    def test_add_collection_creates_one_run_and_associates_all_rows(self) -> None:
        self.store.initialize()
        records = (Evidence("z", "first", _UTC_TIME), Evidence("a", "second"),
                   Evidence("z", "third", _UTC_TIME))
        run_id = self.store.add_collection(iter(records), collected_at=_UTC_TIME)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute(
                "SELECT id, collected_at FROM collection_runs"
            ).fetchall(), [(run_id, _UTC_TIME.isoformat())])
            self.assertEqual(connection.execute(
                "SELECT collection_id FROM evidence ORDER BY id"
            ).fetchall(), [(run_id,)] * 3)
        self.assertEqual(self.store.list_collection_evidence(run_id), records)
        self.assertEqual(self.store.list_evidence(), records)

    def test_multiple_runs_keep_duplicate_evidence_distinct(self) -> None:
        self.store.initialize()
        record = Evidence("source", "same observation", _UTC_TIME)
        first = self.store.add_collection([record], collected_at=_UTC_TIME)
        second = self.store.add_collection([record], collected_at=_UTC_TIME)
        self.assertNotEqual(first, second)
        self.assertEqual(self.store.list_collection_evidence(first), (record,))
        self.assertEqual(self.store.list_collection_evidence(second), (record,))
        self.assertEqual(self.store.list_evidence(), (record, record))

    def test_list_collections_returns_newest_first_with_exact_timestamps(self) -> None:
        self.store.initialize()
        earlier = _UTC_TIME - timedelta(hours=1)
        first_id = self.store.add_collection([], collected_at=earlier)
        second_id = self.store.add_collection([], collected_at=_UTC_TIME)

        collections = self.store.list_collections()

        self.assertEqual(
            collections,
            (
                CollectionRun(second_id, _UTC_TIME),
                CollectionRun(first_id, earlier),
            ),
        )
        self.assertIsInstance(collections, tuple)
        with self.assertRaises(TypeError):
            collections[0] = CollectionRun(99, _UTC_TIME)

    def test_list_collections_returns_empty_tuple_without_runs(self) -> None:
        self.store.initialize()

        self.assertEqual(self.store.list_collections(), ())

    def test_initialize_preserves_collection_associations(self) -> None:
        self.store.initialize()
        record = Evidence("source", "content")
        run_id = self.store.add_collection([record], collected_at=_UTC_TIME)
        self.store.initialize()
        self.store.initialize()
        self.assertEqual(self.store.list_collection_evidence(run_id), (record,))
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute(
                "SELECT id, collected_at FROM collection_runs"
            ).fetchall(), [(run_id, _UTC_TIME.isoformat())])

    def test_empty_collection_creates_a_run(self) -> None:
        self.store.initialize()
        run_id = self.store.add_collection([], collected_at=_UTC_TIME)
        self.assertEqual(self.store.list_collection_evidence(run_id), ())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute(
                "SELECT id FROM collection_runs"
            ).fetchall(), [(run_id,)])

    def test_unknown_collection_returns_empty_tuple(self) -> None:
        self.store.initialize()
        self.assertEqual(self.store.list_collection_evidence(999), ())

    def test_collection_time_accepts_non_utc_offset(self) -> None:
        self.store.initialize()
        collected_at = _UTC_TIME.astimezone(timezone(timedelta(hours=-5)))
        run_id = self.store.add_collection([], collected_at=collected_at)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute(
                "SELECT collected_at FROM collection_runs WHERE id = ?", (run_id,)
            ).fetchone(), (collected_at.isoformat(),))

    def test_collection_rejects_naive_time_before_consuming_evidence(self) -> None:
        self.store.initialize()
        def unexpected_iteration() -> Iterator[Evidence]:
            self.fail("Evidence must not be consumed for an invalid collection time")
            yield Evidence("unused", "unused")
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            self.store.add_collection(unexpected_iteration(), collected_at=datetime(2026, 10, 5))
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT * FROM collection_runs").fetchall(), [])

    def test_collection_rejects_non_datetime_time(self) -> None:
        self.store.initialize()
        with self.assertRaisesRegex(TypeError, "must be a datetime"):
            self.store.add_collection([], collected_at="2026-10-05")  # type: ignore[arg-type]

    def test_collection_insert_failure_rolls_back_run_and_evidence(self) -> None:
        self.store.initialize()
        existing = Evidence("existing", "keep")
        existing_id = self.store.add_collection([existing], collected_at=_UTC_TIME)
        invalid = Evidence(None, "violates NOT NULL")  # type: ignore[arg-type]
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.add_collection([Evidence("valid", "rollback"), invalid], collected_at=_UTC_TIME)
        self.assertEqual(self.store.list_evidence(), (existing,))
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT id FROM collection_runs").fetchall(), [(existing_id,)])

    def test_collection_iterator_failure_rolls_back_run_and_evidence(self) -> None:
        self.store.initialize()
        def failing_snapshot() -> Iterator[Evidence]:
            yield Evidence("first", "rollback")
            # An independent connection cannot see either uncommitted insertion.
            with closing(sqlite3.connect(self.path)) as connection:
                self.assertEqual(connection.execute("SELECT * FROM collection_runs").fetchall(), [])
                self.assertEqual(connection.execute("SELECT * FROM evidence").fetchall(), [])
            raise RuntimeError("snapshot failed")
        with self.assertRaisesRegex(RuntimeError, "snapshot failed"):
            self.store.add_collection(failing_snapshot(), collected_at=_UTC_TIME)
        self.assertEqual(self.store.list_evidence(), ())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT * FROM collection_runs").fetchall(), [])

    def test_foreign_keys_enforced_on_each_store_connection(self) -> None:
        self.store.initialize()
        run_id = self.store.add_collection([Evidence("source", "content")], collected_at=_UTC_TIME)
        for _ in range(2):
            with self.store._connection() as connection, connection:
                self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone(), (1,))
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT INTO evidence (source, content, collection_id) VALUES ('bad', 'bad', ?)",
                        (run_id + 1,),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("DELETE FROM collection_runs WHERE id = ?", (run_id,))

    def test_standalone_inserts_have_no_collection(self) -> None:
        self.store.initialize()
        record = Evidence("source", "standalone")
        self.assertEqual(self.store.add(record), 1)
        self.assertEqual(self.store.add_many([record, record]), (2, 3))
        self.assertEqual(self.store.list_evidence(), (record,) * 3)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT collection_id FROM evidence").fetchall(), [(None,)] * 3)
            self.assertEqual(connection.execute("SELECT * FROM collection_runs").fetchall(), [])

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
