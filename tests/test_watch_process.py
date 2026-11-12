"""The real worker process: starts, collects appends, stops on SIGTERM or a stop file."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from .conftest import append, write_config


def start(tmp_path):
    source = tmp_path / "rag.jsonl"
    source.touch()
    config = write_config(
        tmp_path, [{"type": "jsonl", "name": "rag", "path": "rag.jsonl", "agent": "rag"}]
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agentmon",
            "watch",
            "--config",
            str(config),
            "--state",
            str(tmp_path / "state"),
            "--interval",
            "1",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process, source, tmp_path / "state"


def wait_for(process, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(process.stderr.read().decode())
        try:
            if predicate():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    raise AssertionError("worker did not reach the expected state")


def health(state):
    return json.loads((state / "health.json").read_text())


@pytest.mark.parametrize("stop", ["sigterm", "stop-file"])
def test_worker_collects_and_stops_cleanly(tmp_path, stop):
    process, source, state = start(tmp_path)
    try:
        wait_for(process, lambda: health(state)["status"] == "ok")
        now = time.time()
        append(
            source,
            {"id": "1", "ts": now, "agent": "rag", "run_id": "r", "type": "run_started"},
            {
                "id": "2",
                "ts": now,
                "agent": "rag",
                "run_id": "r",
                "type": "answer",
                "citations": ["fake"],
                "retrieved": ["real"],
            },
            {
                "id": "3",
                "ts": now,
                "agent": "rag",
                "run_id": "r",
                "type": "run_finished",
                "status": "success",
            },
        )
        wait_for(process, lambda: health(state)["highFindings"] == 1)
        if stop == "sigterm":
            process.send_signal(signal.SIGTERM)
        else:
            (state / "stop").touch()
        assert process.wait(timeout=10) == 0
        assert "opened high citation_mismatch" in process.stderr.read().decode()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
