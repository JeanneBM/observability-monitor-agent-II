"""Read-only analysis: events in, findings out."""

from __future__ import annotations

from collections.abc import Iterable

from .drift import Baseline, agent_stats, drift_findings
from .policy import Policy
from .rules import CATALOG, MAX_EVIDENCE, RUN_RULES
from .runs import Run, group_runs
from .schema import Event, Finding


def unknown_agents(runs: Iterable[Run], policy: Policy) -> list[Finding]:
    """One finding per unknown agent, not per run, so a rogue agent is one incident."""
    seen: dict[str, list[Run]] = {}
    for run in runs:
        if policy.agent(run.agent) is None:
            seen.setdefault(run.agent, []).append(run)
    severity = CATALOG["unknown_agent"][0]
    return [
        Finding(
            "unknown_agent",
            severity,
            agent,
            None,
            "policy",
            f"agent {agent!r} has no policy entry; {len(agent_runs)} run(s) cannot be checked",
            tuple(r.first.id for r in agent_runs[:MAX_EVIDENCE]),
        )
        for agent, agent_runs in seen.items()
    ]


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-f.severity, f.agent, f.run_id or "", f.rule, f.subject),
    )


def analyze(
    events: Iterable[Event],
    policy: Policy,
    *,
    baseline: Baseline | None = None,
    now: float | None = None,
) -> list[Finding]:
    """Apply every rule. ``now`` enables time-based rules such as run_stalled."""
    runs = group_runs(events)
    findings = unknown_agents(runs, policy)
    for run in runs:
        agent_policy = policy.agent(run.agent)
        if agent_policy is None:
            continue
        for rule in RUN_RULES:
            findings.extend(rule(run, agent_policy, now))
    if baseline:
        findings.extend(drift_findings(runs, policy, baseline))
    return sort_findings(findings)


def build_baseline(events: Iterable[Event]) -> Baseline:
    return agent_stats(group_runs(events))
