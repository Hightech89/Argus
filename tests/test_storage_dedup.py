"""Authoritative journal-cursor storage policy and safe upgrades."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from argus.models import Evidence
from argus.storage import EvidenceStore

NOW = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)


def journal(cursor: object = None, *, message: str = "Accepted publickey for joshpi from 192.0.2.1 port 22") -> Evidence:
    content: dict[str, object] = {"MESSAGE": message, "__REALTIME_TIMESTAMP": "1791633600000000"}
    if cursor is not None:
        content["__CURSOR"] = cursor
    return Evidence("linux.auth.raw", json.dumps(content), NOW)


class JournalCursorStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "argus.db"
        self.store = EvidenceStore(self.path)
        self.store.initialize()

    def test_first_record_and_distinct_cursors_are_persisted(self) -> None:
        first, second = journal("cursor-a"), journal("cursor-b")
        run_id = self.store.add_collection([first, second], collected_at=NOW)

        self.assertEqual(self.store.list_collection_evidence(run_id), (first, second))
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT cursor FROM linux_auth_cursors ORDER BY cursor").fetchall(),
                [("cursor-a",), ("cursor-b",)],
            )

    def test_repeated_cursor_is_skipped_but_run_and_other_sources_remain(self) -> None:
        first = journal("cursor-a")
        first_id = self.store.add_collection([first], collected_at=NOW)
        later = Evidence("linux.auth.raw", first.content, NOW.replace(hour=13))
        status = Evidence("linux.auth.records_count", "1", NOW.replace(hour=13))
        second_id = self.store.add_collection([status, later], collected_at=NOW.replace(hour=13))

        self.assertEqual(self.store.list_collection_evidence(first_id), (first,))
        self.assertEqual(self.store.list_collection_evidence(second_id), (status,))
        self.assertEqual(len(self.store.list_collections()), 2)
        self.assertEqual(self.store.list_evidence(), (first, status))

    def test_run_with_only_repeated_journal_record_is_audited(self) -> None:
        record = journal("cursor-a")
        self.store.add_collection([record], collected_at=NOW)
        second_id = self.store.add_collection([record], collected_at=NOW)
        self.assertEqual(self.store.list_collection_evidence(second_id), ())
        self.assertEqual(len(self.store.list_collections()), 2)

    def test_cursorless_unusable_and_malformed_records_are_never_dropped(self) -> None:
        records = [journal(), journal(" "), journal(5), Evidence("linux.auth.raw", "{bad", NOW)]
        self.store.add_collection(records, collected_at=NOW)
        second_id = self.store.add_collection(records, collected_at=NOW)
        self.assertEqual(self.store.list_collection_evidence(second_id), tuple(records))

    def test_same_cursor_twice_in_one_run_stores_first_only(self) -> None:
        first = journal(" cursor-a ")
        second = journal("cursor-a", message="Accepted password for joshpi from 192.0.2.1 port 22")
        run_id = self.store.add_collection([first, second], collected_at=NOW)
        self.assertEqual(self.store.list_collection_evidence(run_id), (first,))

    def test_rollback_restores_cursor_availability(self) -> None:
        record = journal("cursor-a")
        invalid = Evidence(None, "invalid", NOW)  # type: ignore[arg-type]
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.add_collection([record, invalid], collected_at=NOW)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT * FROM linux_auth_cursors").fetchall(), [])
            self.assertEqual(connection.execute("SELECT * FROM collection_runs").fetchall(), [])
        run_id = self.store.add_collection([record], collected_at=NOW)
        self.assertEqual(self.store.list_collection_evidence(run_id), (record,))

    def test_existing_duplicates_backfill_without_deleting_evidence(self) -> None:
        # Build a pre-index Home SOC database, including repeated cursor observations.
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TABLE linux_auth_cursors")
            connection.execute("INSERT INTO collection_runs (collected_at) VALUES (?)", (NOW.isoformat(),))
            connection.execute("INSERT INTO collection_runs (collected_at) VALUES (?)", (NOW.isoformat(),))
            old = journal("cursor-a")
            connection.execute(
                "INSERT INTO evidence (source, content, observed_at, collection_id) VALUES (?, ?, ?, 1)",
                (old.source, old.content, NOW.isoformat()),
            )
            connection.execute(
                "INSERT INTO evidence (source, content, observed_at, collection_id) VALUES (?, ?, ?, 2)",
                (old.source, old.content, NOW.isoformat()),
            )
        self.store.initialize()
        self.store.initialize()
        self.assertEqual(self.store.list_evidence(), (old, old))
        new_id = self.store.add_collection([old], collected_at=NOW)
        self.assertEqual(self.store.list_collection_evidence(new_id), ())
        self.assertEqual(len(self.store.list_collections()), 3)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT cursor, evidence_id FROM linux_auth_cursors").fetchall(),
                [("cursor-a", 1)],
            )

    def test_standalone_raw_inserts_register_cursor_without_changing_add_semantics(self) -> None:
        record = journal("cursor-a")
        self.assertEqual(self.store.add_many([record, record]), (1, 2))
        run_id = self.store.add_collection([record], collected_at=NOW)
        self.assertEqual(self.store.list_evidence(), (record, record))
        self.assertEqual(self.store.list_collection_evidence(run_id), ())


if __name__ == "__main__":
    unittest.main()
