"""Regression tests for the issues found when reviewing the first Agent Monitor PoC.

Each test reproduces one probe from that review and asserts the corrected behaviour.
"""

import json

import pytest

from agentmon.collect.base import Ingestor
from agentmon.collect.jsonl import JsonlSource, JsonlSourceConfig
from agentmon.collect.kubernetes import KubernetesSource, KubernetesSourceConfig
from agentmon.engine import analyze, build_baseline
from agentmon.incidents import IncidentLedger
from agentmon.policy import PolicyError, policy_from_dict
from agentmon.schema import Event, Finding, Severity, hash_args
from agentmon.store import Store

from .conftest import NOW, builder, record
from .test_drift import runs_for
from .test_kubernetes_source import FakeTransport, pod


def test_recurring_source_outage_alerts_every_time(tmp_path):
    """v1: three outages of one source produced a single alert row, ever."""
    with Store(tmp_path / "s.sqlite") as store:
        ledger = IncidentLedger(store.db, resolve_after=1)
        down = Finding("source_unavailable", Severity.HIGH, "source:ci", None, "source", "gone")
        opened = 0
        for t in range(3):
            opened += sum(x.kind == "opened" for x in ledger.reconcile([down], t * 2))
            ledger.reconcile([], t * 2 + 1)
        assert opened == 3


def test_ongoing_drift_is_one_incident(tmp_path, policy):
    """v1: one ongoing drift over 20 runs produced 11 alert rows (message in the fingerprint)."""
    baseline = build_baseline(runs_for("diagnostic", "base", 100, 10))
    with Store(tmp_path / "s.sqlite") as store:
        ledger = IncidentLedger(store.db)
        events = []
        opened = 0
        for i in range(20):
            events += runs_for("diagnostic", f"d{i}", 1, 1, t0=NOW + i)
            findings = analyze(events, policy, baseline=baseline)
            opened += sum(x.kind == "opened" for x in ledger.reconcile(findings, i))
        assert opened == 1


def test_oversized_line_does_not_block_the_source(tmp_path):
    """v1: one 70 KB line kept the source 'unavailable' on every following cycle."""
    path = tmp_path / "t.jsonl"
    path.write_text(
        json.dumps(record(id="a"))
        + "\n"
        + "x" * 70_000
        + "\n"
        + json.dumps(record(id="b", type="run_finished", status="success"))
        + "\n"
    )
    with Store(tmp_path / "s.sqlite") as store:
        source = JsonlSource(JsonlSourceConfig("rag", path, frozenset({"rag"})))
        first = source.collect(Ingestor(store, now=NOW, max_age_seconds=86_400))
        second = source.collect(Ingestor(store, now=NOW, max_age_seconds=86_400))
        assert first.status == "degraded"
        assert second.status == "watching"
        assert store.count_events() == 2


def test_policy_authorized_is_accepted():
    """v1: the AKS producer emitted policy_authorized and the monitor rejected it."""
    assert (
        Event.from_dict(record(type="policy_authorized", tool="kubectl_patch")).type
        == "policy_authorized"
    )


def test_tool_loop_without_args_hash_is_detected(policy):
    """v1: identical calls without args_hash were never counted as a loop."""
    b = builder("diagnostic", "loop").start()
    for _ in range(20):
        b.tool("kubectl_logs", hashed=False)
    assert {f.rule for f in analyze(b.finish(), policy)} == {"tool_loop"}


def test_kubernetes_selector_and_roles_are_configuration(tmp_path):
    """v1: selector app=agentic-ops and roles diagnostic/remediation were hard-coded, and a
    missing role made the whole source unavailable."""
    config = KubernetesSourceConfig(
        name="k",
        namespace="ns",
        selector="team=search",
        agent_label="agent",
        expected_agents=frozenset({"rag", "ranker"}),
    )
    transport = FakeTransport([pod("p", "rag", label="agent")])
    with Store(tmp_path / "s.sqlite") as store:
        report = KubernetesSource(config, transport).collect(
            Ingestor(store, now=NOW, max_age_seconds=1e6)
        )
    assert transport.calls[0][1] == {"labelSelector": "team=search"}
    assert report.status == "degraded"  # not unavailable
    assert [p.rule for p in report.problems] == ["agent_missing"]


def test_policy_typo_is_a_clear_error():
    """v1: a typo in policy.json crashed with a raw TypeError traceback."""
    with pytest.raises(PolicyError, match="did you mean 'allowed_tools'"):
        policy_from_dict({"agents": {"a": {"allowed_tool": ["x"]}}})


def test_argument_fingerprints_can_be_keyed():
    """v1: an unsalted 10-hex SHA-1 let anyone confirm guessed arguments."""
    guess = hash_args({"pod": "payments-7f9c"})
    assert hash_args({"pod": "payments-7f9c"}, key=b"producer-secret") != guess
