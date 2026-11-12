import json
import os
from collections import Counter

import pytest

from agentmon.collect.base import Ingestor, SourceReport
from agentmon.collect.jsonl import JsonlSource, JsonlSourceConfig
from agentmon.store import Store

from .conftest import NOW, append, record


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "state.sqlite") as s:
        yield s


def source(path, agents=("rag",), **kw):
    return JsonlSource(JsonlSourceConfig("rag", path, frozenset(agents), **kw))


def collect(src, store, now=NOW):
    return src.collect(Ingestor(store, now=now, max_age_seconds=86_400))


def rules(report):
    return Counter(p.rule for p in report.problems)


def test_partial_record_waits_for_the_writer(tmp_path, store):
    path = tmp_path / "t.jsonl"
    line = json.dumps(record()) + "\n"
    path.write_text(line[:10])
    src = source(path)
    assert collect(src, store).new_events == 0
    with path.open("a") as handle:
        handle.write(line[10:])
    report = collect(src, store)
    assert (report.new_events, report.problems) == (1, [])


def test_oversized_record_is_skipped_and_reading_continues(tmp_path, store):
    path = tmp_path / "t.jsonl"
    path.write_text("x" * 5000 + "\n")
    append(path, record(id="after"))
    report = collect(source(path, max_line_bytes=1000), store)
    assert report.status == "degraded"
    assert [p.subject for p in report.problems] == ["oversized"]
    assert report.new_events == 1
    assert collect(source(path, max_line_bytes=1000), store).status == "watching"


def test_oversized_record_still_being_written(tmp_path, store):
    path = tmp_path / "t.jsonl"
    path.write_text("y" * 3000)  # no newline yet
    src = source(path, max_line_bytes=1000)
    assert [p.subject for p in collect(src, store).problems] == ["oversized"]
    with path.open("a") as handle:
        handle.write("y" * 3000 + "\n" + json.dumps(record(id="ok")) + "\n")
    report = collect(src, store)
    assert (report.new_events, report.problems) == (1, [])


def test_rotation_replays_new_file_without_duplicates(tmp_path, store):
    path = tmp_path / "t.jsonl"
    append(path, record(id="a"), record(id="b"))
    src = source(path)
    assert collect(src, store).new_events == 2
    rotated = tmp_path / "t.jsonl.1"
    path.rename(rotated)
    append(path, record(id="a"), record(id="c"))
    report = collect(src, store)
    assert report.details["rewound"] is True
    assert report.new_events == 1
    assert store.count_events() == 3


def test_copytruncate_that_grew_past_the_offset_is_detected(tmp_path, store):
    path = tmp_path / "t.jsonl"
    append(path, record(id="a"))
    src = source(path)
    collect(src, store)
    with path.open("w") as handle:  # same inode, new content, longer than before
        for n in range(5):
            handle.write(json.dumps(record(id=f"new-{n}")) + "\n")
    report = collect(src, store)
    assert report.details.get("rewound") is True
    assert report.new_events == 5


def test_source_identity_is_enforced(tmp_path, store):
    path = tmp_path / "t.jsonl"
    append(path, record(agent="remediation", id="spoof"), record(id="mine"))
    report = collect(source(path), store)
    assert rules(report) == {"source_identity_mismatch": 1}
    assert report.new_events == 1


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("{not json", "invalid_json"),
        (json.dumps(record(type="bogus")), "unknown_type"),
        (json.dumps(record(ts=NOW + 3600)), "future_timestamp"),
        (json.dumps(record(ts=NOW - 2 * 86_400)), "stale_timestamp"),
        (json.dumps([1, 2]), "not_object"),
    ],
)
def test_rejected_records_are_counted_by_reason(tmp_path, store, line, code):
    path = tmp_path / "t.jsonl"
    path.write_text(line + "\n" + json.dumps(record(id="good")) + "\n")
    report = collect(source(path), store)
    assert [(p.rule, p.subject) for p in report.problems] == [("invalid_telemetry", code)]
    assert report.new_events == 1
    assert report.details["rejectedTotal"] == 1


def test_attributes_are_reduced_to_the_allowlist(tmp_path, store):
    path = tmp_path / "t.jsonl"
    attrs = {"claim_id": "c", "prompt": "secret", "verifier": {"nested": 1}, "reason": "x" * 500}
    append(path, record(type="claim", status="fixed", attrs=attrs))
    collect(source(path), store)
    [event] = store.events()
    assert dict(event.attrs) == {"claim_id": "c"}


def test_event_id_reuse_with_different_data_is_flagged(tmp_path, store):
    path = tmp_path / "t.jsonl"
    append(path, record(id="same"), record(id="same", type="run_finished", status="success"))
    report = collect(source(path), store)
    assert rules(report) == {"event_id_collision": 1}


def test_missing_and_unreadable_files(tmp_path, store):
    report = collect(source(tmp_path / "missing.jsonl"), store)
    assert (report.status, report.details["error"]) == ("unavailable", "missing")
    assert rules(report) == {"source_unavailable": 1}
    locked = tmp_path / "locked.jsonl"
    locked.write_text("")
    os.chmod(locked, 0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("running as a user who bypasses file permissions")
        assert collect(source(locked), store).status == "unavailable"
    finally:
        os.chmod(locked, 0o600)


def test_byte_budget_leaves_a_backlog(tmp_path, store):
    path = tmp_path / "t.jsonl"
    append(path, *(record(id=f"e{n}") for n in range(50)))
    src = source(path, max_bytes_per_cycle=500)
    first = collect(src, store)
    assert 0 < first.new_events < 50
    assert first.details["lagBytes"] > 0
    while collect(src, store).details["lagBytes"]:
        pass
    assert store.count_events() == 50


def test_report_problem_status_rules():
    report = SourceReport("s", "jsonl")
    report.problem("credential_expiring", "credential", "soon")
    assert report.status == "watching"  # low severity does not degrade
    report.problem("invalid_telemetry", "x", "bad")
    assert report.status == "degraded"
