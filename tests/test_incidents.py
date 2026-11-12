import pytest

from agentmon.incidents import IncidentLedger
from agentmon.schema import Finding, Severity
from agentmon.store import Store


@pytest.fixture
def ledger(tmp_path):
    store = Store(tmp_path / "state.sqlite")
    yield IncidentLedger(store.db, resolve_after=2)
    store.close()


def f(rule="source_unavailable", message="down", severity=Severity.HIGH, run_id=None, agent="a"):
    return Finding(rule, severity, agent, run_id, "subject", message)


def kinds(transitions):
    return [(t.kind, t.incident["id"]) for t in transitions]


def test_lifecycle_open_update_resolve(ledger):
    assert kinds(ledger.reconcile([f()], 1)) == [("opened", 1)]
    assert ledger.reconcile([f(message="still down")], 2) == []
    assert ledger.list()[0]["message"] == "still down"
    assert ledger.list()[0]["cyclesSeen"] == 2
    assert ledger.reconcile([], 3) == []  # hysteresis: one quiet cycle is not enough
    [resolved] = ledger.reconcile([], 4)
    assert resolved.kind == "resolved"
    assert resolved.incident["resolution"] == "cleared"
    assert ledger.list() == []


def test_flapping_within_hysteresis_keeps_one_incident(ledger):
    ledger.reconcile([f()], 1)
    ledger.reconcile([], 2)
    assert ledger.reconcile([f()], 3) == []
    assert len(ledger.list(include_resolved=True)) == 1


def test_recurrence_after_resolution_is_a_new_incident(ledger):
    ids = []
    for outage in range(3):
        t = outage * 10
        [opened] = ledger.reconcile([f()], t)
        ids.append(opened.incident["id"])
        ledger.reconcile([], t + 1)
        ledger.reconcile([], t + 2)
    assert ids == [1, 2, 3]


def test_changing_message_does_not_create_incidents(ledger):
    opened = []
    for n in range(20):
        opened += [t for t in ledger.reconcile([f(message=f"rate {n}%")], n) if t.kind == "opened"]
    assert len(opened) == 1


def test_severity_increase_is_an_escalation(ledger):
    ledger.reconcile([f(severity=Severity.MEDIUM)], 1)
    [escalated] = ledger.reconcile([f(severity=Severity.CRITICAL)], 2)
    assert escalated.kind == "escalated"
    assert escalated.incident["severity"] == "critical"
    assert ledger.reconcile([f(severity=Severity.MEDIUM)], 3) == []
    assert ledger.list()[0]["severity"] == "critical"  # never silently downgraded


def test_run_incident_expires_with_its_run(ledger):
    ledger.reconcile([f(rule="run_failed", run_id="r1")], 1, live_runs={("a", "r1")})
    ledger.reconcile([], 2, live_runs=set())
    [resolved] = ledger.reconcile([], 3, live_runs=set())
    assert resolved.incident["resolution"] == "expired"


def test_duplicate_keys_in_one_cycle_merge_to_most_severe(ledger):
    [opened] = ledger.reconcile([f(severity=Severity.LOW), f(severity=Severity.HIGH)], 1)
    assert opened.incident["severity"] == "high"


def test_acknowledge_and_purge(ledger):
    ledger.reconcile([f()], 1)
    item = ledger.acknowledge(1, "joanna", 5)
    assert (item["acknowledgedBy"], item["acknowledgedAt"]) == ("joanna", 5)
    with pytest.raises(KeyError):
        ledger.acknowledge(99, "x", 5)
    ledger.reconcile([], 2)
    ledger.reconcile([], 3)
    assert ledger.purge(cutoff=2) == 0
    assert ledger.purge(cutoff=4) == 1
    assert ledger.list(include_resolved=True) == []


def test_resolve_after_must_be_positive(tmp_path):
    with Store(tmp_path / "s.sqlite") as store, pytest.raises(ValueError, match="at least 1"):
        IncidentLedger(store.db, resolve_after=0)
