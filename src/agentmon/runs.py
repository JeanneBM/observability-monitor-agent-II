"""Grouping of events into agent runs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from .schema import Event


@dataclass(frozen=True, slots=True)
class Run:
    agent: str
    run_id: str
    events: tuple[Event, ...]

    @property
    def first(self) -> Event:
        return self.events[0]

    @property
    def last(self) -> Event:
        return self.events[-1]

    @property
    def terminal(self) -> Event | None:
        """The first ``run_finished`` event, or None while the run is in flight."""
        return next((e for e in self.events if e.type == "run_finished"), None)

    def of_type(self, kind: str) -> list[Event]:
        return [e for e in self.events if e.type == kind]


def group_runs(events: Iterable[Event]) -> list[Run]:
    """Group events by (agent, run_id), each run ordered by (ts, id)."""
    buckets: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        buckets[(event.agent, event.run_id)].append(event)
    return [
        Run(agent, run_id, tuple(sorted(items, key=lambda e: (e.ts, e.id))))
        for (agent, run_id), items in sorted(buckets.items())
    ]
