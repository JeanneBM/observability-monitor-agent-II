import json

import pytest

from agentmon.collect.base import SourceReport
from agentmon.config import ConfigError, config_from_dict, load_config
from agentmon.worker import Monitor

from .conftest import NOW, append, record, write_config


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


def monitor(tmp_path, sources=None, clock=None, **extra):
    sources = sources or [{"type": "jsonl", "name": "rag", "path": "rag.jsonl", "agent": "rag"}]
    config = load_config(write_config(tmp_path, sources, **extra))
    return Monitor(config, tmp_path / "state", clock=clock or Clock())


def alerts(tmp_path):
    path = tmp_path / "state" / "alerts.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def bad_answer(run="q1"):
    return [
        record(id=f"{run}-1", run_id=run, type="run_started"),
        record(id=f"{run}-2", run_id=run, type="tool_call", tool="retrieve", args_hash="h"),
        record(id=f"{run}-3", run_id=run, type="answer", citations=["x"], retrieved=["y"]),
        record(id=f"{run}-4", run_id=run, type="run_finished", status="success"),
    ]


def test_cycle_publishes_reports_and_alerts(tmp_path):
    (tmp_path / "rag.jsonl").touch()
    m = monitor(tmp_path)
    health = m.cycle()
    assert health["status"] == "ok"
    assert health["agents"]["rag"]["idle"] is True
    append(tmp_path / "rag.jsonl", *bad_answer())
    health = m.cycle()
    assert health["openIncidents"]["high"] == 1
    state = tmp_path / "state"
    [finding] = json.loads((state / "findings.json").read_text())
    assert finding["rule"] == "citation_mismatch"
    [incident] = json.loads((state / "incidents.json").read_text())
    assert incident["key"] == finding["key"]
    assert [a["transition"] for a in alerts(tmp_path)] == ["opened"]
    m.close()


def test_restart_keeps_cursor_and_incidents(tmp_path):
    append(tmp_path / "rag.jsonl", *bad_answer())
    m = monitor(tmp_path)
    m.cycle()
    m.close()
    m = monitor(tmp_path)
    health = m.cycle()
    assert health["sources"]["rag"]["newEvents"] == 0
    assert [a["transition"] for a in alerts(tmp_path)] == ["opened"]  # not opened twice
    m.close()


def test_missing_source_degrades_health_and_opens_an_incident(tmp_path):
    m = monitor(tmp_path)
    health = m.cycle()
    assert health["status"] == "degraded"
    assert health["sources"]["rag"]["status"] == "unavailable"
    assert alerts(tmp_path)[0]["incident"]["rule"] == "source_unavailable"
    (tmp_path / "rag.jsonl").touch()
    m.cycle()
    m.cycle()
    assert [a["transition"] for a in alerts(tmp_path)] == ["opened", "resolved"]
    m.close()


def test_retention_drops_whole_runs_and_expires_their_incidents(tmp_path):
    clock = Clock()
    append(tmp_path / "rag.jsonl", *bad_answer())
    m = monitor(tmp_path, clock=clock, retentionHours=1)
    m.cycle()
    clock.t += 2 * 3600
    m.cycle()
    m.cycle()
    assert m.store.count_events() == 0
    resolved = [a for a in alerts(tmp_path) if a["transition"] == "resolved"]
    assert resolved[0]["incident"]["resolution"] == "expired"
    m.close()


def test_stalled_run_is_detected_by_the_clock(tmp_path):
    clock = Clock()
    append(tmp_path / "rag.jsonl", record(id="s", run_id="slow", type="run_started"))
    m = monitor(tmp_path, clock=clock)
    assert m.cycle()["openIncidents"]["high"] == 0
    clock.t += 3600
    assert m.cycle()["openIncidents"]["high"] == 1
    m.close()


def test_a_crashing_source_does_not_stop_the_others(tmp_path):
    class Broken:
        name, kind = "broken", "test"

        def collect(self, ingestor):
            raise RuntimeError("bug")

    class Fine:
        name, kind = "fine", "test"

        def collect(self, ingestor):
            return SourceReport("fine", "test")

    config = load_config(
        write_config(tmp_path, [{"type": "jsonl", "name": "x", "path": "x", "agent": "rag"}])
    )
    m = Monitor(config, tmp_path / "state", clock=Clock(), sources=[Broken(), Fine()])
    health = m.cycle()
    assert health["sources"]["broken"] == {
        "kind": "test",
        "status": "unavailable",
        "newEvents": 0,
        "rejected": 0,
        "error": "internal_error",
    }
    assert health["sources"]["fine"]["status"] == "watching"
    m.close()


def test_token_coverage_reports_missing_provider_usage(tmp_path):
    append(
        tmp_path / "rag.jsonl",
        record(id="a", type="llm_call", tokens=10, attrs={"usage_available": True}),
        record(id="b", type="llm_call", attrs={"usage_available": False}),
    )
    m = monitor(tmp_path)
    assert m.cycle()["agents"]["rag"]["tokenUsageComplete"] is False
    m.close()


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (
            {"policy": "p", "sources": [{"type": "jsonl", "name": "a", "path": "x", "agent": "r"}]},
            "instance",
        ),
        ({"instance": "i", "policy": "p", "sources": []}, "nonempty list"),
        ({"instance": "i", "policy": "p", "source": []}, "did you mean 'sources'"),
        (
            {
                "instance": "i",
                "policy": "p",
                "sources": [{"type": "jsonl", "name": "a", "path": "x"}],
            },
            "bind the source",
        ),
        (
            {"instance": "i", "policy": "p", "sources": [{"type": "s3", "name": "a"}]},
            "type must be",
        ),
        (
            {
                "instance": "i",
                "policy": "p",
                "sources": [
                    {"type": "jsonl", "name": "a", "path": "x", "agent": "r"},
                    {"type": "jsonl", "name": "a", "path": "y", "agent": "r"},
                ],
            },
            "unique",
        ),
        (
            {
                "instance": "i",
                "policy": "p",
                "sources": [
                    {"type": "kubernetes", "name": "k", "namespace": "n", "transport": "ssh"}
                ],
            },
            "transport",
        ),
        (
            {
                "instance": "i",
                "policy": "p",
                "sources": [
                    {
                        "type": "kubernetes",
                        "name": "k",
                        "namespace": "n",
                        "credentialExpiresAt": "soon",
                    }
                ],
            },
            "credentialExpiresAt",
        ),
    ],
)
def test_config_validation(tmp_path, raw, message):
    with pytest.raises(ConfigError, match=message):
        config_from_dict(raw, tmp_path)


def test_relative_paths_resolve_against_the_config_file(tmp_path):
    config = config_from_dict(
        {
            "instance": "i",
            "policy": "conf/p.json",
            "stateDir": "state",
            "sources": [
                {"type": "jsonl", "name": "a", "path": "t/a.jsonl", "agent": "r"},
                {
                    "type": "kubernetes",
                    "name": "k",
                    "namespace": "n",
                    "kubeconfig": "ro.yaml",
                    "credentialExpiresAt": "2027-01-01T00:00:00Z",
                },
            ],
        },
        tmp_path,
    )
    assert config.policy == tmp_path / "conf/p.json"
    assert config.sources[0].path == tmp_path / "t/a.jsonl"
    assert config.sources[1].kubeconfig == str(tmp_path / "ro.yaml")
    assert config.sources[1].source.credential_expires_at == 1798761600.0
