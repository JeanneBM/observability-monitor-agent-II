"""Shared ingestion path for all sources.

Records are validated against the telemetry contract, bound to the identity of
the source they came from, reduced to an allowlist of attributes and stored
idempotently. Problems are reported as findings with stable reason codes; raw
log lines and rejected payloads are never persisted.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection
from dataclasses import dataclass, field, replace
from typing import Any, Final, Protocol

from ..schema import MAX_TEXT_LENGTH, Event, Finding, Severity, TelemetryError
from ..store import Store

ALLOWED_ATTRS: Final = frozenset(
    {"claim_id", "verifier", "error_type", "usage_available", "reason", "approver"}
)

SOURCE_CATALOG: Final[dict[str, tuple[Severity, str]]] = {
    "source_unavailable": (Severity.HIGH, "a telemetry source cannot be read; coverage is lost"),
    "source_identity_mismatch": (
        Severity.HIGH,
        "a record claims an agent identity its source is not bound to",
    ),
    "event_id_collision": (Severity.HIGH, "an event id was reused for different data"),
    "agent_missing": (Severity.HIGH, "an expected agent has no pod behind the selector"),
    "invalid_telemetry": (Severity.MEDIUM, "records rejected by the telemetry contract"),
    "collection_error": (Severity.MEDIUM, "part of a source could not be read this cycle"),
    "collection_truncated": (Severity.MEDIUM, "a read hit its size limit; telemetry may be lost"),
    "agent_unhealthy": (Severity.MEDIUM, "an agent pod is not ready"),
    "credential_expiring": (Severity.LOW, "the collector credential expires within a day"),
}


def source_finding(rule: str, source: str, subject: str, message: str) -> Finding:
    return Finding(rule, SOURCE_CATALOG[rule][0], f"source:{source}", None, subject, message)


def _scalar(value: Any) -> bool:
    if isinstance(value, str):
        return len(value) <= MAX_TEXT_LENGTH
    return isinstance(value, bool | int | float)


@dataclass
class SourceReport:
    name: str
    kind: str
    status: str = "watching"  # watching | degraded | unavailable
    new_events: int = 0
    rejected: int = 0
    details: dict[str, Any] = field(default_factory=dict)
    problems: list[Finding] = field(default_factory=list)

    def problem(self, rule: str, subject: str, message: str) -> None:
        self.problems.append(source_finding(rule, self.name, subject, message))
        if self.status == "watching" and SOURCE_CATALOG[rule][0] >= Severity.MEDIUM:
            self.status = "degraded"

    def unavailable(self, code: str, message: str) -> SourceReport:
        self.status = "unavailable"
        self.problems.append(
            source_finding("source_unavailable", self.name, "source", f"{message} ({code})")
        )
        self.details["error"] = code
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "status": self.status,
            "newEvents": self.new_events,
            "rejected": self.rejected,
            **self.details,
        }


class Ingestor:
    """Validates and stores records for one cycle."""

    def __init__(
        self, store: Store, *, now: float, max_age_seconds: float, max_future_seconds: float = 300
    ) -> None:
        self.store = store
        self.now = now
        self.max_age_seconds = max_age_seconds
        self.max_future_seconds = max_future_seconds

    def ingest(
        self,
        raw: Any,
        report: SourceReport,
        expected_agents: Collection[str],
        rejections: Counter[str],
    ) -> None:
        try:
            event = Event.from_dict(raw)
        except TelemetryError as exc:
            rejections[exc.code] += 1
            return
        if event.ts > self.now + self.max_future_seconds:
            rejections["future_timestamp"] += 1
            return
        if event.ts < self.now - self.max_age_seconds:
            rejections["stale_timestamp"] += 1
            return
        if expected_agents and event.agent not in expected_agents:
            report.problem(
                "source_identity_mismatch",
                f"agent:{event.agent}",
                f"record claims agent {event.agent!r}; source is bound to "
                f"{sorted(expected_agents)}",
            )
            report.rejected += 1
            return
        attrs = {k: v for k, v in event.attrs.items() if k in ALLOWED_ATTRS and _scalar(v)}
        outcome = self.store.put_event(replace(event, attrs=attrs), report.name)
        if outcome == "new":
            report.new_events += 1
        elif outcome == "collision":
            report.problem(
                "event_id_collision", "event_id", "an event id was reused for different data"
            )
            report.rejected += 1

    @staticmethod
    def flush_rejections(report: SourceReport, rejections: Counter[str]) -> None:
        for code, count in sorted(rejections.items()):
            report.rejected += count
            report.problem(
                "invalid_telemetry", code, f"{count} record(s) rejected this cycle ({code})"
            )


class Source(Protocol):
    name: str
    kind: str

    def collect(self, ingestor: Ingestor) -> SourceReport: ...
