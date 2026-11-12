import math

import pytest

from agentmon.schema import Event, Finding, Severity, TelemetryError, hash_args, parse_lines

from .conftest import record


def test_roundtrip_keeps_every_field():
    raw = record(
        type="answer",
        citations=["a"],
        retrieved=["a", "b"],
        tokens=12,
        cost_usd=0.5,
        latency_ms=3,
        status="ok",
        attrs={"claim_id": "c"},
    )
    event = Event.from_dict(raw)
    assert Event.from_dict(event.to_dict()) == event
    assert event.citations == ("a",)


def test_defaults_are_omitted_on_the_wire():
    assert Event.from_dict(record()).to_dict() == record()


@pytest.mark.parametrize("kind", ["policy_authorized", "policy_denied"])
def test_approval_gate_events_are_part_of_the_contract(kind):
    assert Event.from_dict(record(type=kind, tool="kubectl_patch")).tool == "kubectl_patch"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"type": "nope"}, "unknown_type"),
        ({"id": ""}, "bad_type"),
        ({"agent": None}, "missing_field"),
        ({"ts": math.nan}, "bad_value"),
        ({"ts": True}, "bad_value"),
        ({"tokens": -1}, "bad_value"),
        ({"tokens": True}, "bad_type"),
        ({"tokens": 1.5}, "bad_value"),
        ({"cost_usd": math.inf}, "bad_value"),
        ({"citations": "doc"}, "bad_type"),
        ({"retrieved": [1]}, "bad_type"),
        ({"attrs": []}, "bad_type"),
        ({"id": "x" * 201}, "too_long"),
        ({"type": "tool_call"}, "missing_field"),
        ({"type": "policy_authorized"}, "missing_field"),
    ],
)
def test_contract_violations_have_stable_codes(changes, code):
    with pytest.raises(TelemetryError) as info:
        Event.from_dict(record(**changes))
    assert info.value.code == code


def test_non_object_is_rejected():
    with pytest.raises(TelemetryError, match="not_object"):
        Event.from_dict(["not", "an", "object"])


def test_error_never_echoes_payload():
    with pytest.raises(TelemetryError) as info:
        Event.from_dict(record(type="tool_call", args_hash=7, tool="x", secret="hunter2"))
    assert "hunter2" not in str(info.value)


def test_hash_args_is_stable_and_keyed():
    assert hash_args({"a": 1, "b": 2}) == hash_args({"b": 2, "a": 1})
    assert hash_args({"pod": "x"}) != hash_args({"pod": "y"})
    assert hash_args({"pod": "x"}, b"k1") != hash_args({"pod": "x"})
    assert hash_args({"pod": "x"}, b"k1") != hash_args({"pod": "x"}, b"k2")


def test_finding_key_ignores_message_and_evidence():
    a = Finding("r", Severity.HIGH, "agent", "run", "subject", "3 calls", ("e1",))
    b = Finding("r", Severity.HIGH, "agent", "run", "subject", "4 calls", ("e2",))
    assert a.key == b.key == "r|agent|run|subject"


def test_parse_lines_reports_line_number_not_content():
    with pytest.raises(TelemetryError) as info:
        parse_lines(['{"id":"1"}', "", "{broken"], origin="f.jsonl")
    assert info.value.code == "unknown_type"
    assert "f.jsonl:1" in str(info.value)
    with pytest.raises(TelemetryError, match=r"f\.jsonl:2"):
        parse_lines(
            ['{"id":"1","ts":1,"agent":"a","run_id":"r","type":"run_started"}', "{x"],
            origin="f.jsonl",
        )


def test_severity_parse():
    assert Severity.parse("Critical") is Severity.CRITICAL
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("urgent")
