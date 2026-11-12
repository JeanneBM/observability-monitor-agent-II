import dataclasses
import json
import time
from pathlib import Path

import pytest

from agentmon import rules
from agentmon.cli import main
from agentmon.evaluation.harness import evaluate, format_report, scenarios
from agentmon.evaluation.traffic import reference_policy

from .conftest import append, record, write_config

POLICY = str(Path(__file__).parents[1] / "examples" / "policy.json")


# evaluation ------------------------------------------------------------------


def test_reference_evaluation_passes():
    report = evaluate(reference_policy())  # 20 seeds: enough to judge drift precision
    assert report.passed, format_report(report)
    assert {s.id for s in scenarios()} >= {"C00", "N01", "M01", "M16"}


def test_statistical_rules_need_enough_seeds():
    few = evaluate(reference_policy(), seeds=(2,))  # seed 2 has one chance drift alarm
    assert few.passed
    assert not few.statistical_judged
    assert "not judged" in format_report(few)


def test_evaluation_catches_a_broken_rule(monkeypatch):
    weakened = tuple(r for r in rules.RUN_RULES if r is not rules.permission_violation)
    monkeypatch.setattr("agentmon.engine.RUN_RULES", weakened)
    report = evaluate(reference_policy(), seeds=(1,))
    assert not report.passed
    assert report.per_rule()["permission_violation"]["recall"] == 0.0


def test_evaluation_catches_a_noisy_rule(monkeypatch):
    real = rules.tool_loop

    def noisy(run, policy, now):  # a loop rule that fires on any repeated call
        return real(run, dataclasses.replace(policy, max_identical_calls=1), now)

    monkeypatch.setattr(
        "agentmon.engine.RUN_RULES", tuple(noisy if r is real else r for r in rules.RUN_RULES)
    )
    report = evaluate(reference_policy(), seeds=(1,))
    assert not report.passed
    assert report.per_rule()["tool_loop"]["fp"] > 0


# CLI -------------------------------------------------------------------------


def test_generate_then_analyze(tmp_path, capsys):
    assert main(["generate", "--out", str(tmp_path)]) == 0
    baseline = str(tmp_path / "baseline.json")
    assert (
        main(["analyze", str(tmp_path / "C00.jsonl"), "--policy", POLICY, "--baseline", baseline])
        == 0
    )
    assert main(["analyze", str(tmp_path / "M01.jsonl"), "--policy", POLICY, "--json"]) == 1
    out = capsys.readouterr().out
    findings = json.loads(out[out.index("[") :])
    assert findings[0]["rule"] == "permission_violation"


def test_fail_on_threshold(tmp_path):
    main(["generate", "--out", str(tmp_path)])
    events = str(tmp_path / "M02.jsonl")  # tool_loop: medium
    assert main(["analyze", events, "--policy", POLICY]) == 0
    assert main(["analyze", events, "--policy", POLICY, "--fail-on", "medium"]) == 1


def test_errors_exit_with_two(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"agents": {"a": {"allowed_tool": []}}}')
    assert main(["validate", "--policy", str(bad)]) == 2
    assert "did you mean" in capsys.readouterr().err
    broken = tmp_path / "e.jsonl"
    broken.write_text("{nope\n")
    assert main(["analyze", str(broken), "--policy", POLICY]) == 2


def test_eval_command(capsys):
    assert main(["eval", "--seeds", "1"]) == 0
    assert "PASS" in capsys.readouterr().out
    assert main(["eval", "--seeds", "1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["passed"] is True


def test_baseline_and_validate_config(tmp_path, capsys):
    main(["generate", "--out", str(tmp_path)])
    assert (
        main(
            ["baseline", str(tmp_path / "baseline_events.jsonl"), "--out", str(tmp_path / "b.json")]
        )
        == 0
    )
    config = write_config(
        tmp_path, [{"type": "jsonl", "name": "r", "path": "r.jsonl", "agent": "rag"}]
    )
    assert main(["validate", "--config", str(config)]) == 0


def test_watch_incidents_ack_and_health(tmp_path, capsys):
    source = tmp_path / "rag.jsonl"
    append(source, record(ts=time.time(), type="answer", citations=["x"], retrieved=["y"]))
    config = write_config(
        tmp_path, [{"type": "jsonl", "name": "rag", "path": "rag.jsonl", "agent": "rag"}]
    )
    state = str(tmp_path / "state")
    assert main(["watch", "--config", str(config), "--state", state, "--once"]) == 0
    assert main(["health", "--state", state]) == 0
    assert main(["health", "--state", state, "--max-age", "0"]) == 1
    capsys.readouterr()
    assert main(["incidents", "--state", state, "--json"]) == 0
    [incident] = json.loads(capsys.readouterr().out)
    assert (
        main(["incidents", "--state", state, "--ack", str(incident["id"]), "--by", "joanna"]) == 0
    )
    assert json.loads(capsys.readouterr().out)["acknowledgedBy"] == "joanna"
    assert main(["incidents", "--state", state]) == 0
    assert "ack:joanna" in capsys.readouterr().out
    assert main(["incidents", "--state", state, "--ack", "999"]) == 2


def test_watch_needs_a_state_directory(tmp_path):
    config = write_config(
        tmp_path, [{"type": "jsonl", "name": "r", "path": "r.jsonl", "agent": "rag"}]
    )
    assert main(["watch", "--config", str(config), "--once"]) == 2


def test_health_require_ok(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "health.json").write_text(json.dumps({"updatedAt": time.time(), "status": "degraded"}))
    assert main(["health", "--state", str(state)]) == 0
    assert main(["health", "--state", str(state), "--require-ok"]) == 1
    assert main(["health", "--state", str(tmp_path / "none")]) == 1


@pytest.mark.parametrize("command", [["--version"]])
def test_version(command, capsys):
    with pytest.raises(SystemExit):
        main(command)
    assert "agentmon 0.1.0" in capsys.readouterr().out
