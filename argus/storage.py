"""Local SQLite persistence for collected evidence."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from argus.models import Evidence

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

    def add(self, evidence: Evidence) -> int:
        """Persist one Evidence record and return its insertion ID."""
        with self._connection() as connection, connection:
            cursor = connection.execute(_INSERT_EVIDENCE, _evidence_values(evidence))
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return an Evidence row ID")
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
                connection.execute(
                    "INSERT INTO evidence "
                    "(source, content, observed_at, collection_id) VALUES (?, ?, ?, ?)",
                    (*_evidence_values(record), collection_id),
                )
        return collection_id

    def list_collection_evidence(self, collection_id: int) -> tuple[Evidence, ...]:
        """Return a snapshot's observations in insertion order, or an empty tuple."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT source, content, observed_at FROM evidence "
                "WHERE collection_id = ? ORDER BY id",
                (collection_id,),
            ).fetchall()
        return tuple(_evidence_from_row(row) for row in rows)

    def list_evidence(self) -> tuple[Evidence, ...]:
        """Return all persisted Evidence records in insertion order."""
        with self._connection() as connection:
            rows = connection.execute(_SELECT_EVIDENCE).fetchall()
        return tuple(_evidence_from_row(row) for row in rows)

    @contextmanager
    def _connection(self, *, create: bool = False) -> Iterator[sqlite3.Connection]:
        if not create and not self.path.is_file():
            raise RuntimeError("EvidenceStore must be initialized before use")
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
        finally:
            connection.close()


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
