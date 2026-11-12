from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest

from agentmon.evaluation.traffic import REFERENCE_POLICY, RunBuilder, reference_policy
from agentmon.policy import Policy, policy_from_dict

NOW = 1_800_000_000.0


def record(**values: Any) -> dict[str, Any]:
    """A valid wire record; override any field."""
    base: dict[str, Any] = {
        "id": "e1",
        "ts": NOW,
        "agent": "rag",
        "run_id": "r1",
        "type": "run_started",
    }
    base.update(values)
    return base


def builder(agent: str, run_id: str, t0: float = NOW - 3600) -> RunBuilder:
    return RunBuilder(agent, run_id, t0, random.Random(0))


@pytest.fixture
def policy() -> Policy:
    return reference_policy()


def make_policy(**agent_overrides: dict[str, Any]) -> Policy:
    raw = json.loads(json.dumps(REFERENCE_POLICY))
    for agent, values in agent_overrides.items():
        raw["agents"].setdefault(agent, {"allowed_tools": []}).update(values)
    return policy_from_dict(raw)


def write_config(tmp_path: Path, sources: list[dict[str, Any]], **extra: Any) -> Path:
    (tmp_path / "policy.json").write_text(json.dumps(REFERENCE_POLICY))
    config = {"instance": "test", "policy": "policy.json", "sources": sources, **extra}
    path = tmp_path / "sources.json"
    path.write_text(json.dumps(config))
    return path


def append(path: Path, *records: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for item in records:
            handle.write(json.dumps(item) + "\n")
