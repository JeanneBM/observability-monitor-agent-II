"""Behavioural drift of recent runs against a known-good baseline.

The current window is the latest ``drift.window_runs`` finished runs per agent,
so a sudden change is not diluted by older traffic in the retention window.

A drift finding needs both a practically relevant effect (policy thresholds) and
statistical evidence (one-sided p-value below ``significance``):

* escalation rate: Fisher's exact test, which stays correct for small windows
  where the normal approximation is far too optimistic;
* tool calls per run: a Welch-type z-test on the means (large-sample
  approximation, guarded by the ``tool_calls_ratio`` effect size).

The test runs every cycle, so ``significance`` bounds the false-alarm rate per
evaluation, not per day; keep it strict.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .policy import Policy
from .runs import Run
from .schema import Finding, Severity

BASELINE_VERSION = 1


@dataclass(frozen=True, slots=True)
class AgentStats:
    runs: int
    escalated: int
    tool_calls: float  # sum over runs
    tool_calls_sq: float  # sum of squares over runs

    @property
    def escalation_rate(self) -> float:
        return self.escalated / self.runs if self.runs else 0.0

    @property
    def mean_tool_calls(self) -> float:
        return self.tool_calls / self.runs if self.runs else 0.0

    @property
    def var_tool_calls(self) -> float:
        if self.runs < 2:
            return 0.0
        mean = self.mean_tool_calls
        return max(0.0, (self.tool_calls_sq - self.runs * mean * mean) / (self.runs - 1))


Baseline = Mapping[str, AgentStats]


def agent_stats(runs: Iterable[Run], window: int | None = None) -> dict[str, AgentStats]:
    """Per-agent statistics over finished runs; with ``window``, only the latest runs."""
    finished: dict[str, list[tuple[float, str, Run]]] = {}
    for run in runs:
        terminal = run.terminal
        if terminal is not None:
            finished.setdefault(run.agent, []).append((terminal.ts, run.run_id, run))
    out = {}
    for agent, items in finished.items():
        items.sort(key=lambda item: (item[0], item[1]))
        selected = [run for _, _, run in (items[-window:] if window else items)]
        calls = [float(len(run.of_type("tool_call"))) for run in selected]
        escalated = sum(
            1 for run in selected if run.terminal and run.terminal.status == "escalated"
        )
        out[agent] = AgentStats(len(selected), escalated, sum(calls), sum(c * c for c in calls))
    return out


def upper_tail(z: float) -> float:
    """P(Z >= z) for a standard normal variable."""
    return 0.5 * math.erfc(z / math.sqrt(2))


def _log_comb(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def escalation_p_value(current: AgentStats, base: AgentStats) -> float:
    """One-sided Fisher exact test: is the current escalation rate higher?

    Under the null both samples share one rate, so the number of escalations that
    fall into the current window is hypergeometric; the p-value is its upper tail.
    """
    total = current.runs + base.runs
    escalations = current.escalated + base.escalated
    denominator = _log_comb(total, current.runs)
    upper = min(current.runs, escalations)
    tail = sum(
        math.exp(
            _log_comb(escalations, k)
            + _log_comb(total - escalations, current.runs - k)
            - denominator
        )
        for k in range(current.escalated, upper + 1)
        if current.runs - k <= total - escalations
    )
    return min(1.0, tail)


def tool_calls_p_value(current: AgentStats, base: AgentStats) -> float:
    """One-sided Welch-type z-test on mean tool calls per run (large-sample approximation)."""
    se = math.sqrt(current.var_tool_calls / current.runs + base.var_tool_calls / base.runs)
    diff = current.mean_tool_calls - base.mean_tool_calls
    if se == 0:
        return 0.0 if diff > 0 else 1.0
    return upper_tail(diff / se)


def drift_findings(runs: Iterable[Run], policy: Policy, baseline: Baseline) -> list[Finding]:
    drift = policy.drift
    out = []
    for agent, current in sorted(agent_stats(runs, drift.window_runs).items()):
        base = baseline.get(agent)
        if base is None or base.runs < 2 or current.runs < drift.min_runs:
            continue
        rise = current.escalation_rate - base.escalation_rate
        p = escalation_p_value(current, base)
        if rise >= drift.escalation_delta and p < drift.significance:
            out.append(
                Finding(
                    "behavior_drift",
                    Severity.MEDIUM,
                    agent,
                    None,
                    "escalation_rate",
                    f"escalation rate {current.escalation_rate:.0%} vs baseline "
                    f"{base.escalation_rate:.0%} over {current.runs} runs (p={p:.1e})",
                )
            )
        mean, base_mean = current.mean_tool_calls, base.mean_tool_calls
        p = tool_calls_p_value(current, base)
        if base_mean > 0 and mean / base_mean >= drift.tool_calls_ratio and p < drift.significance:
            out.append(
                Finding(
                    "behavior_drift",
                    Severity.MEDIUM,
                    agent,
                    None,
                    "tool_calls",
                    f"mean tool calls/run {mean:.1f} vs baseline {base_mean:.1f} "
                    f"over {current.runs} runs (p={p:.1e})",
                )
            )
    return out


def baseline_to_dict(baseline: Baseline) -> dict[str, Any]:
    return {
        "version": BASELINE_VERSION,
        "agents": {name: asdict(stats) for name, stats in sorted(baseline.items())},
    }


def baseline_from_dict(raw: Any) -> dict[str, AgentStats]:
    if not isinstance(raw, Mapping) or raw.get("version") != BASELINE_VERSION:
        raise ValueError(f"baseline must be an object with version {BASELINE_VERSION}")
    agents = raw.get("agents")
    if not isinstance(agents, Mapping):
        raise ValueError("baseline.agents must be an object")
    out = {}
    for name, row in agents.items():
        try:
            stats = AgentStats(
                runs=int(row["runs"]),
                escalated=int(row["escalated"]),
                tool_calls=float(row["tool_calls"]),
                tool_calls_sq=float(row["tool_calls_sq"]),
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError(f"baseline.agents.{name} is malformed") from None
        if stats.runs < 0 or not 0 <= stats.escalated <= stats.runs:
            raise ValueError(f"baseline.agents.{name} has inconsistent counts")
        out[name] = stats
    return out


def save_baseline(baseline: Baseline, path: str | Path) -> None:
    text = json.dumps(baseline_to_dict(baseline), indent=2) + "\n"
    Path(path).write_text(text, encoding="utf-8")


def load_baseline(path: str | Path) -> dict[str, AgentStats]:
    return baseline_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
