"""Telemetry contract shared with monitored agents (wire format v1).

Every monitored agent emits one JSON object per event. The monitor consumes raw
telemetry only and never another agent's conclusions about itself.

The wire format is intentionally compatible with the first Agent Monitor PoC, so
existing emitters keep working. Two event types were added: ``policy_authorized``
and ``policy_denied``, which record the outcome of an approval gate.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Final

SCHEMA_VERSION: Final = 1

EVENT_TYPES: Final = frozenset(
    {
        "run_started",
        "tool_call",
        "llm_call",
        "escalation",
        "claim",  # the agent states an outcome, e.g. status="fixed"
        "verification",  # an independent check, status="ok" | "failed"
        "answer",  # a RAG answer with citations and retrieved ids
        "policy_authorized",  # an approval gate allowed `tool`
        "policy_denied",  # an approval gate refused `tool`
        "run_finished",  # status="success" | "escalated" | "error"
    }
)

MAX_ID_LENGTH: Final = 200
MAX_TEXT_LENGTH: Final = 200
MAX_REFERENCES: Final = 1_000


class Severity(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None


class TelemetryError(ValueError):
    """A record that violates the telemetry contract.

    ``code`` is a short, stable reason that is safe to persist. The offending
    payload itself is never included, because producers may log secrets.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def hash_args(args: Any, key: bytes | None = None) -> str:
    """Return a stable fingerprint of tool arguments.

    Raw arguments are never part of the telemetry. Without a key this is a plain
    SHA-256 prefix: it detects repetition, but low-entropy arguments such as pod
    names can be recovered by guessing. Pass a secret ``key`` (HMAC-SHA256) when
    the fingerprints leave the producer's trust boundary.
    """
    blob = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str).encode()
    if key:
        return hmac.new(key, blob, hashlib.sha256).hexdigest()[:16]
    return hashlib.sha256(blob).hexdigest()[:16]


def _text(raw: Mapping[str, Any], name: str, *, required: bool, limit: int) -> str | None:
    value = raw.get(name)
    if value is None:
        if required:
            raise TelemetryError("missing_field", name)
        return None
    if not isinstance(value, str) or not value:
        raise TelemetryError("bad_type", f"{name} must be a nonempty string")
    if len(value) > limit:
        raise TelemetryError("too_long", name)
    return value


def _number(raw: Mapping[str, Any], name: str, *, integer: bool = False) -> float:
    value = raw.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TelemetryError("bad_type", f"{name} must be a number")
    if not math.isfinite(value) or value < 0:
        raise TelemetryError("bad_value", f"{name} must be finite and nonnegative")
    if integer and value != int(value):
        raise TelemetryError("bad_value", f"{name} must be an integer")
    return value


def _references(raw: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = raw.get(name, ())
    if not isinstance(value, list | tuple):
        raise TelemetryError("bad_type", f"{name} must be an array")
    if len(value) > MAX_REFERENCES:
        raise TelemetryError("too_long", name)
    if not all(isinstance(v, str) and 0 < len(v) <= MAX_ID_LENGTH for v in value):
        raise TelemetryError("bad_type", f"{name} must contain nonempty strings")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class Event:
    id: str
    ts: float
    agent: str
    run_id: str
    type: str
    tool: str | None = None
    args_hash: str | None = None
    tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    status: str | None = None
    citations: tuple[str, ...] = ()
    retrieved: tuple[str, ...] = ()
    attrs: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> Event:
        """Parse and validate one wire record. Unknown top-level keys are ignored."""
        if not isinstance(raw, Mapping):
            raise TelemetryError("not_object")
        kind = raw.get("type")
        if kind not in EVENT_TYPES:
            raise TelemetryError("unknown_type", repr(kind)[:40])
        ts = raw.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, int | float) or not math.isfinite(ts):
            raise TelemetryError("bad_value", "ts must be a finite number")
        tool = _text(
            raw,
            "tool",
            required=kind in {"tool_call", "policy_authorized", "policy_denied"},
            limit=MAX_TEXT_LENGTH,
        )
        attrs = raw.get("attrs", {})
        if not isinstance(attrs, Mapping):
            raise TelemetryError("bad_type", "attrs must be an object")
        return cls(
            id=_text(raw, "id", required=True, limit=MAX_ID_LENGTH) or "",
            ts=float(ts),
            agent=_text(raw, "agent", required=True, limit=MAX_ID_LENGTH) or "",
            run_id=_text(raw, "run_id", required=True, limit=MAX_ID_LENGTH) or "",
            type=kind,
            tool=tool,
            args_hash=_text(raw, "args_hash", required=False, limit=MAX_TEXT_LENGTH),
            tokens=int(_number(raw, "tokens", integer=True)),
            cost_usd=float(_number(raw, "cost_usd")),
            latency_ms=float(_number(raw, "latency_ms")),
            status=_text(raw, "status", required=False, limit=MAX_TEXT_LENGTH),
            citations=_references(raw, "citations"),
            retrieved=_references(raw, "retrieved"),
            attrs=dict(attrs),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "ts": self.ts,
            "agent": self.agent,
            "run_id": self.run_id,
            "type": self.type,
        }
        optional: dict[str, Any] = {
            "tool": self.tool,
            "args_hash": self.args_hash,
            "tokens": self.tokens or None,
            "cost_usd": self.cost_usd or None,
            "latency_ms": self.latency_ms or None,
            "status": self.status,
            "citations": list(self.citations) or None,
            "retrieved": list(self.retrieved) or None,
            "attrs": dict(self.attrs) or None,
        }
        out.update({k: v for k, v in optional.items() if v is not None})
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected condition.

    ``key`` identifies the condition, not its current wording: the message can
    change between cycles (counts, rates) without creating a new incident.
    """

    rule: str
    severity: Severity
    agent: str
    run_id: str | None
    subject: str
    message: str
    evidence: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return "|".join((self.rule, self.agent, self.run_id or "-", self.subject))

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "rule": self.rule,
            "severity": self.severity.label,
            "agent": self.agent,
            "run_id": self.run_id,
            "subject": self.subject,
            "message": self.message,
            "evidence": list(self.evidence),
        }


def parse_lines(lines: Any, *, origin: str = "<input>") -> list[Event]:
    """Parse JSON Lines strictly; the first invalid record raises with its line number."""
    events: list[Event] = []
    for number, line in enumerate(lines, 1):
        text = line.strip()
        if not text:
            continue
        try:
            events.append(Event.from_dict(json.loads(text)))
        except json.JSONDecodeError:
            raise TelemetryError("invalid_json", f"{origin}:{number}") from None
        except TelemetryError as exc:
            raise TelemetryError(exc.code, f"{origin}:{number}") from None
    return events


def load_events(path: str) -> list[Event]:
    with open(path, encoding="utf-8") as handle:
        return parse_lines(handle, origin=path)


def dump_events(events: Any, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(event.to_json() + "\n")
