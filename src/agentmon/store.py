"""SQLite state: deduplicated events, per-source cursors and the incident ledger."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from .schema import Event

MIGRATIONS = (
    """
    CREATE TABLE events (
        id TEXT PRIMARY KEY,
        agent TEXT NOT NULL,
        run_id TEXT NOT NULL,
        ts REAL NOT NULL,
        source TEXT NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE INDEX events_run ON events (agent, run_id);
    CREATE TABLE cursors (source TEXT PRIMARY KEY, state TEXT NOT NULL);
    CREATE TABLE incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        rule TEXT NOT NULL,
        severity TEXT NOT NULL,
        agent TEXT NOT NULL,
        run_id TEXT,
        subject TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
        opened_at REAL NOT NULL,
        last_seen REAL NOT NULL,
        resolved_at REAL,
        resolution TEXT,
        cycles_seen INTEGER NOT NULL,
        cycles_missing INTEGER NOT NULL,
        acknowledged_at REAL,
        acknowledged_by TEXT,
        message TEXT NOT NULL,
        evidence TEXT NOT NULL
    );
    CREATE UNIQUE INDEX incidents_open_key ON incidents (key) WHERE status = 'open';
    CREATE INDEX incidents_status ON incidents (status, resolved_at);
    """,
)

PutResult = Literal["new", "duplicate", "collision"]


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.execute("PRAGMA synchronous = NORMAL")
        self._migrate()

    def _migrate(self) -> None:
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > len(MIGRATIONS):
            raise RuntimeError(f"state database {self.path} is newer than this agentmon release")
        for number, script in enumerate(MIGRATIONS[version:], start=version + 1):
            with self.db:
                self.db.executescript(script)
                self.db.execute(f"PRAGMA user_version = {number}")

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def commit(self) -> None:
        self.db.commit()

    def rollback(self) -> None:
        self.db.rollback()

    # events -------------------------------------------------------------

    def put_event(self, event: Event, source: str) -> PutResult:
        payload = event.to_json()
        row = self.db.execute("SELECT payload FROM events WHERE id = ?", (event.id,)).fetchone()
        if row is not None:
            return "duplicate" if row["payload"] == payload else "collision"
        self.db.execute(
            "INSERT INTO events (id, agent, run_id, ts, source, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (event.id, event.agent, event.run_id, event.ts, source, payload),
        )
        return "new"

    def events(self) -> list[Event]:
        rows = self.db.execute("SELECT payload FROM events ORDER BY ts, id")
        return [Event.from_dict(json.loads(row["payload"])) for row in rows]

    def count_events(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def purge_runs(self, cutoff: float) -> int:
        """Drop whole runs whose newest event is older than ``cutoff``.

        Runs are kept or dropped as a unit, so an early claim is never separated
        from its later verification.
        """
        cursor = self.db.execute(
            """
            DELETE FROM events WHERE (agent, run_id) IN (
                SELECT agent, run_id FROM events GROUP BY agent, run_id HAVING MAX(ts) < ?
            )
            """,
            (cutoff,),
        )
        return cursor.rowcount

    # cursors ------------------------------------------------------------

    def cursor(self, source: str) -> dict[str, Any]:
        row = self.db.execute("SELECT state FROM cursors WHERE source = ?", (source,)).fetchone()
        return dict(json.loads(row["state"])) if row else {}

    def set_cursor(self, source: str, state: Mapping[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO cursors (source, state) VALUES (?, ?) "
            "ON CONFLICT (source) DO UPDATE SET state = excluded.state",
            (source, json.dumps(dict(state), sort_keys=True)),
        )
