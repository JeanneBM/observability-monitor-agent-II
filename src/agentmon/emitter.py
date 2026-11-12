"""Reference emitter for monitored agents (producer side of the telemetry contract).

    sink = JsonlSink("/var/log/agent/telemetry.jsonl")      # or LogSink() for pod logs
    telemetry = Telemetry("remediation", sink, args_key=secret)
    with telemetry.run() as run:
        run.tool("acr_check", {"image": image})
        run.authorized("kubectl_patch", approver="oncall")
        run.tool("kubectl_patch", {"deployment": name})
        run.claim("fixed", claim_id="c1")
        run.verify("ok", claim_id="c1", verifier="rollout-check")

The context manager always emits ``run_finished``: ``error`` (with the exception
class as ``error_type``) if the block raised, otherwise ``success`` unless
``run.finish()`` was called explicitly. Raw tool arguments never leave the
process, only their fingerprint.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any, Protocol, TextIO

from .schema import Event, hash_args


class Sink(Protocol):
    def write(self, event: Event) -> None: ...


class JsonlSink:
    """Appends one line per event with a single O_APPEND write."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = os.fspath(path)

    def write(self, event: Event) -> None:
        data = (event.to_json() + "\n").encode()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)


class LogSink:
    """Prints the event inside an envelope, for collection from pod logs."""

    def __init__(self, stream: TextIO | None = None, envelope_key: str = "agent_monitor_event"):
        self.stream = stream
        self.envelope_key = envelope_key
        self.lock = threading.Lock()

    def write(self, event: Event) -> None:
        line = json.dumps({self.envelope_key: event.to_dict()}, separators=(",", ":"))
        with self.lock:
            stream = self.stream or sys.stdout
            stream.write(line + "\n")
            stream.flush()


class RunTrace:
    def __init__(self, telemetry: Telemetry, run_id: str) -> None:
        self.telemetry = telemetry
        self.run_id = run_id
        self.sequence = 0
        self.finished = False

    def emit(self, kind: str, **fields: Any) -> Event:
        if self.finished and kind != "run_finished":
            raise RuntimeError("run already finished")
        self.sequence += 1
        event = Event(
            id=f"{self.run_id}-{self.sequence:05d}",
            ts=self.telemetry.clock(),
            agent=self.telemetry.agent,
            run_id=self.run_id,
            type=kind,
            **fields,
        )
        self.telemetry.sink.write(event)
        return event

    def tool(self, name: str, args: Any = None, *, latency_ms: float = 0.0) -> Event:
        digest = hash_args(args, self.telemetry.args_key)
        return self.emit("tool_call", tool=name, args_hash=digest, latency_ms=latency_ms)

    def llm(
        self, tokens: int | None = None, cost_usd: float | None = None, *, latency_ms: float = 0.0
    ) -> Event:
        """Pass ``tokens=None`` when the provider did not report usage; nothing is estimated."""
        return self.emit(
            "llm_call",
            tokens=tokens or 0,
            cost_usd=cost_usd or 0.0,
            latency_ms=latency_ms,
            attrs={"usage_available": tokens is not None},
        )

    def authorized(self, tool: str, *, approver: str | None = None) -> Event:
        return self.emit("policy_authorized", tool=tool, attrs=_attrs(approver=approver))

    def denied(self, tool: str, *, approver: str | None = None) -> Event:
        return self.emit("policy_denied", tool=tool, attrs=_attrs(approver=approver))

    def escalate(self, reason: str) -> Event:
        return self.emit("escalation", attrs={"reason": reason})

    def claim(self, status: str = "fixed", *, claim_id: str | None = None) -> Event:
        return self.emit("claim", status=status, attrs=_attrs(claim_id=claim_id))

    def verify(
        self, status: str, *, claim_id: str | None = None, verifier: str | None = None
    ) -> Event:
        return self.emit(
            "verification", status=status, attrs=_attrs(claim_id=claim_id, verifier=verifier)
        )

    def answer(
        self, citations: Sequence[str], retrieved: Sequence[str], *, abstained: bool = False
    ) -> Event:
        return self.emit(
            "answer",
            citations=tuple(citations),
            retrieved=tuple(retrieved),
            status="abstained" if abstained else None,
        )

    def finish(self, status: str = "success", *, error_type: str | None = None) -> Event:
        event = self.emit("run_finished", status=status, attrs=_attrs(error_type=error_type))
        self.finished = True
        return event


def _attrs(**values: str | None) -> dict[str, str]:
    return {k: v for k, v in values.items() if v is not None}


class Telemetry:
    def __init__(
        self,
        agent: str,
        sink: Sink,
        *,
        args_key: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.agent = agent
        self.sink = sink
        self.args_key = args_key
        self.clock = clock

    @contextmanager
    def run(self, run_id: str | None = None) -> Iterator[RunTrace]:
        trace = RunTrace(self, run_id or uuid.uuid4().hex)
        trace.emit("run_started")
        try:
            yield trace
        except BaseException as exc:
            if not trace.finished:
                trace.finish("error", error_type=type(exc).__name__)
            raise
        if not trace.finished:
            trace.finish("success")
