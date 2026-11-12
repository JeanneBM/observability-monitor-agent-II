"""Continuous observation: collect, analyse, reconcile incidents, publish reports.

Outputs in the state directory:

* ``events.sqlite``  events, cursors and the incident ledger
* ``findings.json``  every condition detected in the latest cycle
* ``incidents.json`` incidents that are currently open
* ``health.json``    the monitor's own health: sources, coverage, heartbeat
* ``alerts.jsonl``   append-only outbox of incident transitions (opened, escalated,
  resolved), meant to be tailed by a log shipper. The monitor itself makes no
  outbound network calls apart from its read-only sources.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from . import __version__
from .collect.base import Ingestor, Source, SourceReport
from .config import MonitorConfig, TransportFactory, build_sources, default_transport
from .drift import load_baseline
from .engine import analyze
from .incidents import IncidentLedger, Transition
from .policy import load_policy
from .runs import group_runs
from .schema import Severity
from .store import Store

log = logging.getLogger("agentmon")


def write_json(path: Path, value: Any) -> None:
    """Atomic replace, so readers never see a half-written report."""
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


class Monitor:
    def __init__(
        self,
        config: MonitorConfig,
        state_dir: str | Path,
        *,
        clock: Callable[[], float] = time.time,
        transport_factory: TransportFactory = default_transport,
        sources: Sequence[Source] | None = None,
    ) -> None:
        self.config = config
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.policy = load_policy(config.policy)
        self.baseline = load_baseline(config.baseline) if config.baseline else None
        self.sources = (
            list(sources) if sources is not None else build_sources(config, transport_factory)
        )
        self.store = Store(self.state_dir / "events.sqlite")
        self.ledger = IncidentLedger(self.store.db, resolve_after=config.resolve_after)

    def close(self) -> None:
        self.store.close()

    def _collect(self, source: Source, ingestor: Ingestor) -> SourceReport:
        try:
            return source.collect(ingestor)
        except Exception:  # a bug in one source must not stop the others
            log.exception("source %s failed", source.name)
            return SourceReport(source.name, source.kind).unavailable(
                "internal_error", "collector raised an unexpected error"
            )

    def cycle(self) -> dict[str, Any]:
        started = time.monotonic()
        now = self.clock()
        cfg = self.config
        ingestor = Ingestor(
            self.store,
            now=now,
            max_age_seconds=cfg.retention_seconds,
            max_future_seconds=cfg.max_future_seconds,
        )
        reports = [self._collect(source, ingestor) for source in self.sources]
        self.store.purge_runs(now - cfg.retention_seconds)
        events = self.store.events()
        findings = analyze(events, self.policy, baseline=self.baseline, now=now)
        findings += [problem for report in reports for problem in report.problems]
        live_runs = {(e.agent, e.run_id) for e in events}
        transitions = self.ledger.reconcile(findings, now, live_runs)
        self.ledger.purge(now - cfg.incident_retention_seconds)
        self._publish_transitions(transitions)  # before commit: at-least-once delivery
        self.store.commit()

        open_incidents = self.ledger.list()
        write_json(self.state_dir / "findings.json", [f.to_dict() for f in findings])
        write_json(self.state_dir / "incidents.json", open_incidents)
        health = self._health(now, reports, events, open_incidents, time.monotonic() - started)
        write_json(self.state_dir / "health.json", health)
        for transition in transitions:
            item = transition.incident
            log.info("%s %s %s %s", transition.kind, item["severity"], item["rule"], item["key"])
        return health

    def _publish_transitions(self, transitions: list[Transition]) -> None:
        if not transitions:
            return
        with open(self.state_dir / "alerts.jsonl", "a", encoding="utf-8") as handle:
            for transition in transitions:
                handle.write(json.dumps(transition.to_dict(), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _health(
        self,
        now: float,
        reports: list[SourceReport],
        events: list[Any],
        open_incidents: list[dict[str, Any]],
        duration: float,
    ) -> dict[str, Any]:
        runs = group_runs(events)
        agents: dict[str, Any] = {}
        for name in sorted(self.policy.agents):
            agent_events = [e for e in events if e.agent == name]
            llm_calls = [e for e in agent_events if e.type == "llm_call"]
            agents[name] = {
                "events": len(agent_events),
                "runs": sum(r.agent == name for r in runs),
                "lastEventAt": max((e.ts for e in agent_events), default=None),
                "idle": not agent_events,
                # None: no llm_call seen; False: some calls did not report provider usage.
                "tokenUsageComplete": (
                    all(e.attrs.get("usage_available", True) is not False for e in llm_calls)
                    if llm_calls
                    else None
                ),
            }
        severities = Counter(item["severity"] for item in open_incidents)
        degraded = any(report.status != "watching" for report in reports)
        return {
            "version": __version__,
            "instance": self.config.instance,
            "pid": os.getpid(),
            "updatedAt": now,
            "cycleSeconds": round(duration, 3),
            "status": "degraded" if degraded else "ok",
            "sources": {report.name: report.to_dict() for report in reports},
            "agents": agents,
            "events": len(events),
            "openIncidents": {s.label: severities.get(s.label, 0) for s in Severity},
            "highFindings": severities.get("high", 0) + severities.get("critical", 0),
        }


def watch(
    config: MonitorConfig,
    state_dir: str | Path,
    *,
    interval: float = 5.0,
    once: bool = False,
    max_consecutive_failures: int = 5,
) -> int:
    """Run cycles until SIGTERM/SIGINT or a ``stop`` file appears in the state directory."""
    if interval < 1:
        raise ValueError("polling interval must be at least one second")
    stop = threading.Event()
    stop_file = Path(state_dir) / "stop"

    def handle(signum: int, frame: FrameType | None) -> None:
        log.info("received signal %s, stopping after this cycle", signum)
        stop.set()

    previous = {sig: signal.signal(sig, handle) for sig in (signal.SIGTERM, signal.SIGINT)}
    monitor = Monitor(config, state_dir)
    failures = 0
    try:
        while not stop.is_set() and not stop_file.exists():
            try:
                monitor.cycle()
                failures = 0
            except Exception:
                failures += 1
                monitor.store.rollback()
                log.exception("cycle failed (%d consecutive)", failures)
                if failures >= max_consecutive_failures:
                    return 1
            if once:
                break
            deadline = time.monotonic() + interval
            while not stop.is_set() and not stop_file.exists():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                stop.wait(min(remaining, 0.2))
    finally:
        monitor.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0
