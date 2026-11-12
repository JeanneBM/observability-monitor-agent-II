"""Monitor configuration (JSON). Relative paths resolve against the config file."""

from __future__ import annotations

import difflib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .collect.base import Source
from .collect.jsonl import JsonlSource, JsonlSourceConfig
from .collect.kubernetes import (
    InClusterTransport,
    KubectlTransport,
    KubernetesSource,
    KubernetesSourceConfig,
    Transport,
    parse_time,
)


class ConfigError(ValueError):
    pass


_TOP = {
    "instance",
    "policy",
    "baseline",
    "stateDir",
    "retentionHours",
    "incidentResolveCycles",
    "incidentRetentionDays",
    "maxFutureSkewSeconds",
    "sources",
}
_JSONL = {"type", "name", "path", "agent", "agents", "maxLineBytes", "maxBytesPerCycle"}
_KUBE = {
    "type",
    "name",
    "namespace",
    "selector",
    "agentLabel",
    "expectedAgents",
    "containers",
    "envelopeKey",
    "overlapSeconds",
    "initialLookbackSeconds",
    "maxLogBytes",
    "credentialExpiresAt",
    "transport",
    "kubeconfig",
    "context",
}


@dataclass(frozen=True, slots=True)
class MonitorConfig:
    instance: str
    policy: Path
    baseline: Path | None
    state_dir: Path | None
    retention_seconds: float
    resolve_after: int
    incident_retention_seconds: float
    max_future_seconds: float
    sources: tuple[JsonlSourceConfig | KubeSourceSpec, ...]


@dataclass(frozen=True, slots=True)
class KubeSourceSpec:
    source: KubernetesSourceConfig
    transport: str
    kubeconfig: str | None
    context: str | None


def _check_keys(raw: Mapping[str, Any], allowed: set[str], where: str) -> None:
    for key in raw:
        if key not in allowed:
            hint = difflib.get_close_matches(key, sorted(allowed), n=1)
            raise ConfigError(
                f"{where}: unknown key {key!r}" + (f"; did you mean {hint[0]!r}?" if hint else "")
            )


def _string(raw: Mapping[str, Any], key: str, where: str, default: str | None = None) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where}.{key} must be a nonempty string")
    return value


def _strings(raw: Mapping[str, Any], key: str, where: str) -> frozenset[str]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ConfigError(f"{where}.{key} must be a list of strings")
    return frozenset(value)


def _number(raw: Mapping[str, Any], key: str, where: str, default: float) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        raise ConfigError(f"{where}.{key} must be a positive number")
    return float(value)


def _jsonl(raw: Mapping[str, Any], where: str, base: Path) -> JsonlSourceConfig:
    _check_keys(raw, _JSONL, where)
    agents = _strings(raw, "agents", where)
    if "agent" in raw:
        agents |= {_string(raw, "agent", where)}
    if not agents:
        raise ConfigError(f"{where}: bind the source to its agent with 'agent' or 'agents'")
    return JsonlSourceConfig(
        name=_string(raw, "name", where),
        path=base / _string(raw, "path", where),
        agents=agents,
        max_line_bytes=int(_number(raw, "maxLineBytes", where, 65_536)),
        max_bytes_per_cycle=int(_number(raw, "maxBytesPerCycle", where, 8 * 1024 * 1024)),
    )


def _kube(raw: Mapping[str, Any], where: str, base: Path) -> KubeSourceSpec:
    _check_keys(raw, _KUBE, where)
    transport = raw.get("transport", "kubectl")
    if transport not in {"kubectl", "in-cluster"}:
        raise ConfigError(f"{where}.transport must be 'kubectl' or 'in-cluster'")
    expires = raw.get("credentialExpiresAt")
    expires_at = parse_time(expires) if isinstance(expires, str) else expires
    if expires is not None and (
        isinstance(expires_at, bool) or not isinstance(expires_at, int | float)
    ):
        raise ConfigError(f"{where}.credentialExpiresAt must be ISO 8601 or epoch seconds")
    kubeconfig = raw.get("kubeconfig")
    if transport == "kubectl" and kubeconfig is not None:
        kubeconfig = str(base / _string(raw, "kubeconfig", where))
    return KubeSourceSpec(
        source=KubernetesSourceConfig(
            name=_string(raw, "name", where),
            namespace=_string(raw, "namespace", where),
            selector=raw.get("selector", "") if isinstance(raw.get("selector", ""), str) else "",
            agent_label=_string(raw, "agentLabel", where, "app.kubernetes.io/component"),
            expected_agents=_strings(raw, "expectedAgents", where),
            containers=_strings(raw, "containers", where),
            envelope_key=_string(raw, "envelopeKey", where, "agent_monitor_event"),
            overlap_seconds=_number(raw, "overlapSeconds", where, 30),
            initial_lookback_seconds=_number(raw, "initialLookbackSeconds", where, 600),
            max_log_bytes=int(_number(raw, "maxLogBytes", where, 4 * 1024 * 1024)),
            credential_expires_at=float(expires_at) if expires_at is not None else None,
        ),
        transport=transport,
        kubeconfig=kubeconfig,
        context=raw.get("context"),
    )


def config_from_dict(raw: Any, base: Path) -> MonitorConfig:
    if not isinstance(raw, Mapping):
        raise ConfigError("config must be a JSON object")
    _check_keys(raw, _TOP, "config")
    sources_raw = raw.get("sources")
    if not isinstance(sources_raw, list) or not sources_raw:
        raise ConfigError("config.sources must be a nonempty list")
    sources: list[JsonlSourceConfig | KubeSourceSpec] = []
    for index, item in enumerate(sources_raw):
        where = f"sources[{index}]"
        if not isinstance(item, Mapping):
            raise ConfigError(f"{where} must be an object")
        kind = item.get("type")
        if kind == "jsonl":
            sources.append(_jsonl(item, where, base))
        elif kind == "kubernetes":
            sources.append(_kube(item, where, base))
        else:
            raise ConfigError(f"{where}.type must be 'jsonl' or 'kubernetes'")
    names = [s.name if isinstance(s, JsonlSourceConfig) else s.source.name for s in sources]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ConfigError(f"source names must be unique: {duplicates}")
    baseline = raw.get("baseline")
    state_dir = raw.get("stateDir")
    resolve_after = raw.get("incidentResolveCycles", 2)
    if isinstance(resolve_after, bool) or not isinstance(resolve_after, int) or resolve_after < 1:
        raise ConfigError("config.incidentResolveCycles must be a positive integer")
    return MonitorConfig(
        instance=_string(raw, "instance", "config"),
        policy=base / _string(raw, "policy", "config"),
        baseline=base / _string(raw, "baseline", "config") if baseline is not None else None,
        state_dir=base / _string(raw, "stateDir", "config") if state_dir is not None else None,
        retention_seconds=_number(raw, "retentionHours", "config", 24) * 3600,
        resolve_after=resolve_after,
        incident_retention_seconds=_number(raw, "incidentRetentionDays", "config", 30) * 86_400,
        max_future_seconds=_number(raw, "maxFutureSkewSeconds", "config", 300),
        sources=tuple(sources),
    )


def load_config(path: str | Path) -> MonitorConfig:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON ({exc.msg}, line {exc.lineno})") from None
    return config_from_dict(raw, path.resolve().parent)


TransportFactory = Callable[[KubeSourceSpec], Transport]


def default_transport(spec: KubeSourceSpec) -> Transport:
    if spec.transport == "in-cluster":
        return InClusterTransport()
    return KubectlTransport(spec.kubeconfig, spec.context)


def build_sources(
    config: MonitorConfig, transport_factory: TransportFactory = default_transport
) -> list[Source]:
    sources: list[Source] = []
    for spec in config.sources:
        if isinstance(spec, JsonlSourceConfig):
            sources.append(JsonlSource(spec))
        else:
            sources.append(KubernetesSource(spec.source, transport_factory(spec)))
    return sources
