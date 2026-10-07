"""Local SQLite persistence for collected evidence."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from argus.models import Evidence

_CREATE_EVIDENCE_TABLE = """
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    content TEXT NOT NULL,
    observed_at TEXT NULL
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
        """Create the database schema without altering existing records."""
        with self._connection(create=True) as connection, connection:
            connection.execute(_CREATE_EVIDENCE_TABLE)

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

    def list_evidence(self) -> tuple[Evidence, ...]:
        """Return all persisted Evidence records in insertion order."""
        with self._connection() as connection:
            rows = connection.execute(_SELECT_EVIDENCE).fetchall()
        return tuple(
            Evidence(
                source=source,
                content=content,
                observed_at=(
                    datetime.fromisoformat(observed_at)
                    if observed_at is not None
                    else None
                ),
            )
            for source, content, observed_at in rows
        )

    @contextmanager
    def _connection(self, *, create: bool = False) -> Iterator[sqlite3.Connection]:
        if not create and not self.path.is_file():
            raise RuntimeError("EvidenceStore must be initialized before use")
        connection = sqlite3.connect(self.path)
        try:
            yield connection
        finally:
            connection.close()


def _evidence_values(evidence: Evidence) -> tuple[object, object, str | None]:
    observed_at = (
        evidence.observed_at.isoformat()
        if evidence.observed_at is not None
        else None
    )
    return evidence.source, evidence.content, observed_at
