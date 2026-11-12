import json
import math

import pytest

from agentmon.drift import (
    AgentStats,
    agent_stats,
    baseline_from_dict,
    escalation_p_value,
    load_baseline,
    save_baseline,
)
from agentmon.engine import analyze, build_baseline
from agentmon.runs import group_runs

from .conftest import NOW, builder


def fisher_upper_tail(x1, n1, x0, n0):
    """Reference implementation with exact integer arithmetic."""
    total, k = n1 + n0, x1 + x0
    return sum(
        math.comb(k, i) * math.comb(total - k, n1 - i) for i in range(x1, min(n1, k) + 1)
    ) / math.comb(total, n1)


@pytest.mark.parametrize(
    ("x1", "n1", "x0", "n0"),
    [(7, 20, 10, 100), (14, 20, 10, 100), (0, 20, 10, 100), (20, 20, 0, 100), (3, 3, 1, 4)],
)
def test_fisher_exact_matches_reference(x1, n1, x0, n0):
    p = escalation_p_value(AgentStats(n1, x1, 0, 0), AgentStats(n0, x0, 0, 0))
    assert p == pytest.approx(fisher_upper_tail(x1, n1, x0, n0), rel=1e-9, abs=1e-15)


def runs_for(agent, prefix, count, escalated, *, calls=1, t0=NOW - 50_000):
    events = []
    for i in range(count):
        b = builder(agent, f"{prefix}-{i:03d}", t0 + i * 100).start()
        for n in range(calls):
            b.tool("kubectl_get", {"n": n})
        events += b.finish("escalated" if i < escalated else "success")
    return events


def test_window_uses_only_the_latest_runs():
    events = runs_for("diagnostic", "old", 50, 0) + runs_for("diagnostic", "new", 20, 20, t0=NOW)
    assert agent_stats(group_runs(events))["diagnostic"].escalated == 20
    windowed = agent_stats(group_runs(events), window=20)["diagnostic"]
    assert (windowed.runs, windowed.escalated) == (20, 20)


def test_unfinished_runs_are_not_counted():
    events = builder("rag", "r").start().events
    assert agent_stats(group_runs(events)) == {}


def test_sudden_jump_is_detected_despite_older_clean_traffic(policy):
    baseline = build_baseline(runs_for("diagnostic", "base", 100, 10))
    events = runs_for("diagnostic", "old", 60, 6) + runs_for("diagnostic", "new", 20, 14, t0=NOW)
    found = {f.key for f in analyze(events, policy, baseline=baseline)}
    assert found == {"behavior_drift|diagnostic|-|escalation_rate"}


def test_unlucky_but_plausible_window_is_not_drift(policy):
    baseline = build_baseline(runs_for("diagnostic", "base", 100, 10))
    events = runs_for("diagnostic", "now", 20, 5)  # 25% vs 10%: below delta, weak evidence
    assert analyze(events, policy, baseline=baseline) == []


def test_too_few_runs_give_no_verdict(policy):
    baseline = build_baseline(runs_for("diagnostic", "base", 100, 10))
    events = runs_for("diagnostic", "now", policy.drift.min_runs - 1, 9)
    assert analyze(events, policy, baseline=baseline) == []


def test_tool_call_drift(policy):
    baseline = build_baseline(
        runs_for("diagnostic", "b1", 50, 0, calls=3) + runs_for("diagnostic", "b2", 50, 0, calls=4)
    )
    events = runs_for("diagnostic", "now", 20, 0, calls=12)
    found = {f.key for f in analyze(events, policy, baseline=baseline)}
    assert found == {"behavior_drift|diagnostic|-|tool_calls"}


def test_drift_key_is_stable_while_numbers_change(policy):
    baseline = build_baseline(runs_for("diagnostic", "base", 100, 10))
    a = analyze(runs_for("diagnostic", "a", 20, 15, t0=NOW), policy, baseline=baseline)
    b = analyze(runs_for("diagnostic", "b", 20, 18, t0=NOW), policy, baseline=baseline)
    assert [f.key for f in a] == [f.key for f in b]
    assert a[0].message != b[0].message


def test_baseline_roundtrip(tmp_path):
    baseline = build_baseline(runs_for("diagnostic", "base", 30, 3, calls=2))
    path = tmp_path / "baseline.json"
    save_baseline(baseline, path)
    assert load_baseline(path) == baseline
    assert json.loads(path.read_text())["version"] == 1


@pytest.mark.parametrize(
    "raw",
    [
        {"agents": {}},
        {"version": 1, "agents": []},
        {"version": 1, "agents": {"a": {"runs": 1}}},
        {
            "version": 1,
            "agents": {"a": {"runs": 1, "escalated": 5, "tool_calls": 0, "tool_calls_sq": 0}},
        },
    ],
)
def test_malformed_baseline_is_rejected(raw):
    with pytest.raises(ValueError, match="baseline"):
        baseline_from_dict(raw)
