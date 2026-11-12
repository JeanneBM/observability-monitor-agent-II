"""Incident ledger: turns per-cycle findings into incidents with a lifecycle.

A finding's ``key`` identifies its condition. While the condition is present the
incident stays open and is updated in place, so changing numbers in a message do
not create new alerts. When the condition is absent for ``resolve_after``
consecutive cycles the incident is resolved. If it comes back later, a new
incident is opened, so a recurring problem alerts every time it recurs.

Resolution reasons:

* ``cleared``: the condition disappeared while its evidence is still retained.
* ``expired``: the run the incident refers to aged out of the retention window.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from .schema import Finding, Severity

TransitionKind = Literal["opened", "escalated", "resolved"]


@dataclass(frozen=True, slots=True)
class Transition:
    kind: TransitionKind
    at: float
    incident: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"transition": self.kind, "at": self.at, "incident": self.incident}


def incident_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "key": row["key"],
        "rule": row["rule"],
        "severity": row["severity"],
        "agent": row["agent"],
        "run_id": row["run_id"],
        "subject": row["subject"],
        "status": row["status"],
        "openedAt": row["opened_at"],
        "lastSeen": row["last_seen"],
        "resolvedAt": row["resolved_at"],
        "resolution": row["resolution"],
        "cyclesSeen": row["cycles_seen"],
        "acknowledgedAt": row["acknowledged_at"],
        "acknowledgedBy": row["acknowledged_by"],
        "message": row["message"],
        "evidence": json.loads(row["evidence"]),
    }


def _merge(findings: Iterable[Finding]) -> dict[str, Finding]:
    """One finding per key; the most severe wins."""
    merged: dict[str, Finding] = {}
    for item in findings:
        prior = merged.get(item.key)
        if prior is None or item.severity > prior.severity:
            merged[item.key] = item
    return merged


class IncidentLedger:
    def __init__(self, db: sqlite3.Connection, *, resolve_after: int = 2) -> None:
        if resolve_after < 1:
            raise ValueError("resolve_after must be at least 1")
        self.db = db
        self.resolve_after = resolve_after

    def _get(self, incident_id: int) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return incident_dict(row)

    def reconcile(
        self,
        findings: Iterable[Finding],
        now: float,
        live_runs: Collection[tuple[str, str]] = (),
    ) -> list[Transition]:
        current = _merge(findings)
        rows = self.db.execute("SELECT * FROM incidents WHERE status = 'open'").fetchall()
        open_by_key = {row["key"]: row for row in rows}
        transitions: list[Transition] = []

        for key, item in sorted(current.items()):
            row = open_by_key.get(key)
            evidence = json.dumps(list(item.evidence))
            if row is None:
                cursor = self.db.execute(
                    """
                    INSERT INTO incidents (key, rule, severity, agent, run_id, subject, status,
                        opened_at, last_seen, cycles_seen, cycles_missing, message, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, 1, 0, ?, ?)
                    """,
                    (
                        key,
                        item.rule,
                        item.severity.label,
                        item.agent,
                        item.run_id,
                        item.subject,
                        now,
                        now,
                        item.message,
                        evidence,
                    ),
                )
                incident_id = cursor.lastrowid or 0  # always set after a successful INSERT
                transitions.append(Transition("opened", now, self._get(incident_id)))
                continue
            escalated = item.severity > Severity.parse(row["severity"])
            self.db.execute(
                """
                UPDATE incidents SET last_seen = ?, cycles_seen = cycles_seen + 1,
                    cycles_missing = 0, message = ?, evidence = ?, severity = ?
                WHERE id = ?
                """,
                (
                    now,
                    item.message,
                    evidence,
                    max(item.severity, Severity.parse(row["severity"])).label,
                    row["id"],
                ),
            )
            if escalated:
                transitions.append(Transition("escalated", now, self._get(row["id"])))

        for key, row in sorted(open_by_key.items()):
            if key in current:
                continue
            missing = row["cycles_missing"] + 1
            if missing < self.resolve_after:
                self.db.execute(
                    "UPDATE incidents SET cycles_missing = ? WHERE id = ?", (missing, row["id"])
                )
                continue
            expired = row["run_id"] is not None and (row["agent"], row["run_id"]) not in live_runs
            self.db.execute(
                """
                UPDATE incidents SET status = 'resolved', resolved_at = ?, resolution = ?,
                    cycles_missing = ?
                WHERE id = ?
                """,
                (now, "expired" if expired else "cleared", missing, row["id"]),
            )
            transitions.append(Transition("resolved", now, self._get(row["id"])))
        return transitions

    def acknowledge(self, incident_id: int, by: str, now: float) -> dict[str, Any]:
        cursor = self.db.execute(
            "UPDATE incidents SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ?",
            (now, by, incident_id),
        )
        if cursor.rowcount == 0:
            raise KeyError(incident_id)
        return self._get(incident_id)

    def list(self, *, include_resolved: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM incidents"
        if not include_resolved:
            query += " WHERE status = 'open'"
        rows = self.db.execute(query + " ORDER BY opened_at, id").fetchall()
        return [incident_dict(row) for row in rows]

    def purge(self, cutoff: float) -> int:
        """Forget resolved incidents resolved before ``cutoff``."""
        cursor = self.db.execute(
            "DELETE FROM incidents WHERE status = 'resolved' AND resolved_at < ?", (cutoff,)
        )
        return cursor.rowcount
