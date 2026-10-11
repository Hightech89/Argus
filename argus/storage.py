"""Local SQLite persistence for collected evidence."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from argus.models import CollectionRun, Evidence

_CREATE_COLLECTION_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at TEXT NOT NULL
)
"""

_CREATE_EVIDENCE_TABLE = """
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    content TEXT NOT NULL,
    observed_at TEXT NULL,
    collection_id INTEGER NULL REFERENCES collection_runs(id)
)
"""

_CREATE_LINUX_AUTH_CURSORS_TABLE = """
CREATE TABLE IF NOT EXISTS linux_auth_cursors (
    cursor TEXT PRIMARY KEY,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id)
)
"""

_INSERT_EVIDENCE = """
INSERT INTO evidence (source, content, observed_at)
VALUES (?, ?, ?)
"""

_SELECT_EVIDENCE = """
SELECT source, content, observed_at
FROM evidence
ORDER BY id
"""


def default_database_path() -> Path:
    """Return the configured or per-user default Argus database path."""
    configured_path = os.environ.get("ARGUS_DB_PATH")
    if configured_path is not None and configured_path.strip():
        return Path(configured_path).expanduser()
    return Path.home() / ".argus" / "argus.db"


@dataclass(frozen=True)
class StorageCounts:
    collection_runs: int
    evidence_records: int
    by_source: tuple[tuple[str, int], ...]


class EvidenceStore:
    """Explicit SQLite storage for Evidence records."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def initialize(self) -> None:
        """Create or upgrade the schema without altering existing records."""
        with self._connection(create=True) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_CREATE_COLLECTION_RUNS_TABLE)
            connection.execute(_CREATE_EVIDENCE_TABLE)
            columns = connection.execute("PRAGMA table_info(evidence)").fetchall()
            if not any(column[1] == "collection_id" for column in columns):
                connection.execute(
                    "ALTER TABLE evidence ADD COLUMN collection_id INTEGER NULL "
                    "REFERENCES collection_runs(id)"
                )
            has_cursor_index = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'linux_auth_cursors'"
            ).fetchone()
            connection.execute(_CREATE_LINUX_AUTH_CURSORS_TABLE)
            if not has_cursor_index:
                for evidence_id, content in connection.execute(
                    "SELECT id, content FROM evidence "
                    "WHERE source = 'linux.auth.raw' ORDER BY id"
                ):
                    cursor = _journal_cursor(content)
                    if cursor is not None:
                        connection.execute(
                            "INSERT OR IGNORE INTO linux_auth_cursors (cursor, evidence_id) "
                            "VALUES (?, ?)",
                            (cursor, evidence_id),
                        )

    def add(self, evidence: Evidence) -> int:
        """Persist one Evidence record and return its insertion ID."""
        with self._connection() as connection, connection:
            cursor = connection.execute(_INSERT_EVIDENCE, _evidence_values(evidence))
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return an Evidence row ID")
            _register_journal_cursor(connection, evidence, cursor.lastrowid)
            return cursor.lastrowid

    def add_many(self, evidence: Iterable[Evidence]) -> tuple[int, ...]:
        """Persist one batch atomically and return IDs in input order."""
        inserted_ids: list[int] = []
        with self._connection() as connection, connection:
            for record in evidence:
                cursor = connection.execute(
                    _INSERT_EVIDENCE,
                    _evidence_values(record),
                )
                if cursor.lastrowid is None:
                    raise RuntimeError("SQLite did not return an Evidence row ID")
                _register_journal_cursor(connection, record, cursor.lastrowid)
                inserted_ids.append(cursor.lastrowid)
        return tuple(inserted_ids)

    def add_collection(
        self, evidence: Iterable[Evidence], *, collected_at: datetime
    ) -> int:
        """Persist a snapshot (including an empty one) in one transaction."""
        if not isinstance(collected_at, datetime):
            raise TypeError("collected_at must be a datetime")
        if collected_at.tzinfo is None or collected_at.utcoffset() is None:
            raise ValueError("collected_at must be timezone-aware")
        with self._connection() as connection, connection:
            cursor = connection.execute(
                "INSERT INTO collection_runs (collected_at) VALUES (?)",
                (collected_at.isoformat(),),
            )
            collection_id = cursor.lastrowid
            if collection_id is None:
                raise RuntimeError("SQLite did not return a collection run ID")
            for record in evidence:
                journal_cursor = (
                    _journal_cursor(record.content)
                    if record.source == "linux.auth.raw" else None
                )
                already_stored = (
                    journal_cursor is not None
                    and connection.execute(
                        "SELECT 1 FROM linux_auth_cursors WHERE cursor = ?",
                        (journal_cursor,),
                    ).fetchone()
                )
                if already_stored:
                    continue
                evidence_cursor = connection.execute(
                    "INSERT INTO evidence "
                    "(source, content, observed_at, collection_id) VALUES (?, ?, ?, ?)",
                    (*_evidence_values(record), collection_id),
                )
                if journal_cursor is not None:
                    connection.execute(
                        "INSERT INTO linux_auth_cursors (cursor, evidence_id) VALUES (?, ?)",
                        (journal_cursor, evidence_cursor.lastrowid),
                    )
        return collection_id

    def storage_counts(self) -> StorageCounts:
        """Return read-only record counts, including empty pre-schema databases."""
        with self._connection(read_only=True) as connection:
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            runs = 0
            if "collection_runs" in tables:
                runs = connection.execute(
                    "SELECT COUNT(*) FROM collection_runs"
                ).fetchone()[0]
            by_source = (
                tuple(
                    connection.execute(
                        "SELECT source, COUNT(*) FROM evidence "
                        "GROUP BY source ORDER BY source"
                    )
                )
                if "evidence" in tables else ()
            )
        return StorageCounts(runs, sum(count for _, count in by_source), by_source)

    def list_collection_evidence(self, collection_id: int) -> tuple[Evidence, ...]:
        """Return a snapshot's observations in insertion order, or an empty tuple."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT source, content, observed_at FROM evidence "
                "WHERE collection_id = ? ORDER BY id",
                (collection_id,),
            ).fetchall()
        return tuple(_evidence_from_row(row) for row in rows)

    def list_collections(self) -> tuple[CollectionRun, ...]:
        """Return collection runs from newest to oldest."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, collected_at FROM collection_runs ORDER BY id DESC"
            ).fetchall()
        return tuple(
            CollectionRun(
                id=collection_id,
                collected_at=datetime.fromisoformat(collected_at),
            )
            for collection_id, collected_at in rows
        )

    def list_evidence(self) -> tuple[Evidence, ...]:
        """Return all persisted Evidence records in insertion order."""
        with self._connection() as connection:
            rows = connection.execute(_SELECT_EVIDENCE).fetchall()
        return tuple(_evidence_from_row(row) for row in rows)

    @contextmanager
    def _connection(
        self, *, create: bool = False, read_only: bool = False
    ) -> Iterator[sqlite3.Connection]:
        if not create and not self.path.is_file():
            raise RuntimeError("EvidenceStore must be initialized before use")
        connection = (
            sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True)
            if read_only
            else sqlite3.connect(self.path)
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
        finally:
            connection.close()


def _journal_cursor(content: str) -> str | None:
    try:
        journal = json.loads(content)
    except (TypeError, ValueError):
        return None
    if not isinstance(journal, dict):
        return None
    cursor = journal.get("__CURSOR")
    return cursor.strip() if isinstance(cursor, str) and cursor.strip() else None


def _register_journal_cursor(
    connection: sqlite3.Connection, evidence: Evidence, evidence_id: int
) -> None:
    if evidence.source != "linux.auth.raw":
        return
    cursor = _journal_cursor(evidence.content)
    if cursor is not None:
        connection.execute(
            "INSERT OR IGNORE INTO linux_auth_cursors (cursor, evidence_id) VALUES (?, ?)",
            (cursor, evidence_id),
        )


def _evidence_from_row(row: tuple[str, str, str | None]) -> Evidence:
    source, content, observed_at = row
    return Evidence(
        source=source,
        content=content,
        observed_at=datetime.fromisoformat(observed_at) if observed_at is not None else None,
    )


def _evidence_values(evidence: Evidence) -> tuple[object, object, str | None]:
    observed_at = (
        evidence.observed_at.isoformat()
        if evidence.observed_at is not None
        else None
    )
    return evidence.source, evidence.content, observed_at
