"""Declarative, strictly validated policy: what each monitored agent may do."""

from __future__ import annotations

import difflib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    """The policy file is invalid. The message names the offending key."""


@dataclass(frozen=True, slots=True)
class AgentPolicy:
    allowed_tools: frozenset[str]
    require_approval_for: frozenset[str] = frozenset()
    max_identical_calls: int = 3
    max_tool_calls_per_run: int | None = None
    max_tokens_per_run: int | None = 20_000
    max_cost_per_run: float | None = None
    max_run_seconds: float | None = None
    run_idle_timeout_seconds: float = 600.0
    require_verification: bool = False
    require_citations: bool = False


@dataclass(frozen=True, slots=True)
class DriftPolicy:
    window_runs: int = 20  # latest finished runs per agent compared with the baseline
    min_runs: int = 10  # no verdict on fewer runs than this
    escalation_delta: float = 0.25  # minimum absolute rise of the escalation rate
    tool_calls_ratio: float = 2.0  # minimum ratio of mean tool calls per run
    significance: float = 0.001  # one-sided p-value threshold, per agent per cycle


@dataclass(frozen=True, slots=True)
class Policy:
    agents: Mapping[str, AgentPolicy] = field(default_factory=dict)
    drift: DriftPolicy = field(default_factory=DriftPolicy)

    def agent(self, name: str) -> AgentPolicy | None:
        return self.agents.get(name)


_TOOL_SETS = {"allowed_tools", "require_approval_for"}
_OPTIONAL_NUMBERS = {
    "max_tool_calls_per_run",
    "max_tokens_per_run",
    "max_cost_per_run",
    "max_run_seconds",
}


def _reject_unknown(raw: Mapping[str, Any], allowed: set[str], where: str) -> None:
    for key in raw:
        if key not in allowed:
            hint = difflib.get_close_matches(key, sorted(allowed), n=1)
            suffix = f"; did you mean {hint[0]!r}?" if hint else ""
            raise PolicyError(f"{where}: unknown key {key!r}{suffix}")


def _positive(value: Any, where: str, *, integer: bool, allow_zero: bool = False) -> Any:
    kind = int if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, kind):
        raise PolicyError(f"{where} must be {'an integer' if integer else 'a number'}")
    if value < 0 or (value == 0 and not allow_zero):
        raise PolicyError(f"{where} must be {'nonnegative' if allow_zero else 'positive'}")
    return value


def _agent_policy(name: str, raw: Any) -> AgentPolicy:
    where = f"agents.{name}"
    if not isinstance(raw, Mapping):
        raise PolicyError(f"{where} must be an object")
    names = {f.name for f in fields(AgentPolicy)}
    _reject_unknown(raw, names, where)
    if "allowed_tools" not in raw:
        raise PolicyError(f"{where}.allowed_tools is required (use [] for no tools)")
    values: dict[str, Any] = {}
    for key, value in raw.items():
        path = f"{where}.{key}"
        if key in _TOOL_SETS:
            if not isinstance(value, list) or not all(isinstance(t, str) and t for t in value):
                raise PolicyError(f"{path} must be a list of tool names")
            values[key] = frozenset(value)
        elif key in _OPTIONAL_NUMBERS:
            integer = key not in {"max_cost_per_run", "max_run_seconds"}
            values[key] = None if value is None else _positive(value, path, integer=integer)
        elif key == "max_identical_calls":
            values[key] = _positive(value, path, integer=True)
        elif key == "run_idle_timeout_seconds":
            values[key] = float(_positive(value, path, integer=False))
        elif key in {"require_verification", "require_citations"}:
            if not isinstance(value, bool):
                raise PolicyError(f"{path} must be true or false")
            values[key] = value
    policy = AgentPolicy(**values)
    outside = policy.require_approval_for - policy.allowed_tools
    if outside:
        raise PolicyError(
            f"{where}.require_approval_for lists tools that are not allowed: {sorted(outside)}"
        )
    return policy


def _drift_policy(raw: Any) -> DriftPolicy:
    if not isinstance(raw, Mapping):
        raise PolicyError("drift must be an object")
    _reject_unknown(raw, {f.name for f in fields(DriftPolicy)}, "drift")
    values: dict[str, Any] = {}
    for key, value in raw.items():
        path = f"drift.{key}"
        values[key] = _positive(value, path, integer=key in {"min_runs", "window_runs"})
    if not 0 < values.get("significance", 0.001) < 1:
        raise PolicyError("drift.significance must be between 0 and 1")
    if values.get("min_runs", 10) < 2:
        raise PolicyError("drift.min_runs must be at least 2")
    if values.get("window_runs", 20) < values.get("min_runs", 10):
        raise PolicyError("drift.window_runs must be at least drift.min_runs")
    return DriftPolicy(**values)


def policy_from_dict(raw: Any) -> Policy:
    if not isinstance(raw, Mapping):
        raise PolicyError("policy must be a JSON object")
    _reject_unknown(raw, {"agents", "drift"}, "policy")
    agents = raw.get("agents", {})
    if not isinstance(agents, Mapping) or not agents:
        raise PolicyError("policy.agents must be a nonempty object")
    return Policy(
        agents={name: _agent_policy(name, cfg) for name, cfg in agents.items()},
        drift=_drift_policy(raw.get("drift", {})),
    )


def load_policy(path: str | Path) -> Policy:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{path}: invalid JSON ({exc.msg}, line {exc.lineno})") from None
    return policy_from_dict(raw)
