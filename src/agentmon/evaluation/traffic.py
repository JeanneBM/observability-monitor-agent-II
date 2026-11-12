"""Synthetic but realistic agent traffic for evaluating the monitor."""

from __future__ import annotations

import random
from typing import Any

from ..policy import Policy, policy_from_dict
from ..schema import Event, hash_args

# The policy the evaluation traffic is designed for; examples/policy.json is a copy.
REFERENCE_POLICY: dict[str, Any] = {
    "agents": {
        "diagnostic": {
            "allowed_tools": ["kubectl_get", "kubectl_describe", "kubectl_logs", "acr_check"],
            "max_identical_calls": 3,
            "max_tool_calls_per_run": 30,
            "max_tokens_per_run": 20000,
        },
        "remediation": {
            "allowed_tools": ["acr_check", "kubectl_patch", "rollout_status"],
            "require_approval_for": ["kubectl_patch"],
            "max_identical_calls": 3,
            "max_tool_calls_per_run": 20,
            "max_tokens_per_run": 20000,
            "require_verification": True,
        },
        "rag": {
            "allowed_tools": ["retrieve"],
            "max_identical_calls": 3,
            "max_tokens_per_run": 12000,
            "require_citations": True,
        },
        "ci-repair": {
            "allowed_tools": ["policy_check", "fixture_validation", "draft_export"],
            "max_tokens_per_run": 50000,
        },
    },
    "drift": {
        "window_runs": 20,
        "min_runs": 10,
        "escalation_delta": 0.25,
        "tool_calls_ratio": 2.0,
        "significance": 0.001,
    },
}


def reference_policy() -> Policy:
    return policy_from_dict(REFERENCE_POLICY)


class RunBuilder:
    def __init__(self, agent: str, run_id: str, t0: float, rng: random.Random) -> None:
        self.agent, self.run_id, self.t, self.rng = agent, run_id, t0, rng
        self.events: list[Event] = []

    def add(self, kind: str, **fields: Any) -> RunBuilder:
        self.t += self.rng.uniform(0.2, 3.0)
        number = len(self.events) + 1
        self.events.append(
            Event(
                id=f"{self.run_id}-{number:03d}",
                ts=round(self.t, 3),
                agent=self.agent,
                run_id=self.run_id,
                type=kind,
                **fields,
            )
        )
        return self

    def start(self) -> RunBuilder:
        return self.add("run_started")

    def llm(self, tokens: int | None = None) -> RunBuilder:
        return self.add("llm_call", tokens=tokens or self.rng.randint(800, 2500))

    def tool(self, name: str, args: Any = None, *, hashed: bool = True) -> RunBuilder:
        return self.add("tool_call", tool=name, args_hash=hash_args(args) if hashed else None)

    def authorized(self, tool: str) -> RunBuilder:
        return self.add("policy_authorized", tool=tool, attrs={"approver": "oncall"})

    def denied(self, tool: str) -> RunBuilder:
        return self.add("policy_denied", tool=tool)

    def claim(self, claim_id: str) -> RunBuilder:
        return self.add("claim", status="fixed", attrs={"claim_id": claim_id})

    def verify(self, status: str, claim_id: str) -> RunBuilder:
        return self.add("verification", status=status, attrs={"claim_id": claim_id})

    def answer(
        self, citations: list[str], retrieved: list[str], abstained: bool = False
    ) -> RunBuilder:
        return self.add(
            "answer",
            citations=tuple(citations),
            retrieved=tuple(retrieved),
            status="abstained" if abstained else None,
        )

    def escalate(self, reason: str) -> RunBuilder:
        return self.add("escalation", attrs={"reason": reason})

    def finish(self, status: str = "success", error_type: str | None = None) -> list[Event]:
        attrs = {"error_type": error_type} if error_type else {}
        self.add("run_finished", status=status, attrs=attrs)
        return self.events


def clean_run(
    agent: str, run_id: str, t0: float, rng: random.Random, escalated: bool
) -> list[Event]:
    """One run that a correct monitor must accept without findings."""
    b = RunBuilder(agent, run_id, t0, rng).start().llm()
    if agent == "diagnostic":
        pod = f"pod-{rng.randint(1, 50)}"
        b.tool("kubectl_get", {"pod": pod}).tool("kubectl_describe", {"pod": pod})
        for _ in range(rng.randint(1, 3)):  # repeated, but within max_identical_calls
            b.tool("kubectl_logs", {"pod": pod})
        b.llm()
        if escalated:
            b.escalate("needs_human")
        return b.finish("escalated" if escalated else "success")
    if agent == "remediation":
        image = f"app:{rng.randint(1, 99)}"
        b.tool("acr_check", {"image": image})
        if escalated:
            if rng.random() < 0.5:
                b.authorized("kubectl_patch").llm()  # approved but agent backed off
            else:
                b.denied("kubectl_patch")
            return b.escalate("checks_failed").finish("escalated")
        deployment = f"deploy-{rng.randint(1, 20)}"
        b.authorized("kubectl_patch").tool("kubectl_patch", {"deployment": deployment})
        for _ in range(rng.randint(1, 3)):
            b.tool("rollout_status", {"deployment": deployment})
        claim = f"{run_id}-claim"
        return b.claim(claim).verify("ok", claim).finish()
    if agent == "rag":
        b.tool("retrieve", {"q": f"question {rng.randint(1, 10_000)}"})
        if escalated:
            return b.escalate("no_sources").finish("escalated")
        if rng.random() < 0.15:
            return b.answer([], [], abstained=True).finish()
        retrieved = [f"doc-{rng.randint(1, 500)}" for _ in range(rng.randint(2, 6))]
        cited = rng.sample(retrieved, rng.randint(1, len(retrieved)))
        return b.answer(cited, retrieved).llm().finish()
    raise ValueError(f"no clean traffic model for {agent!r}")


AGENTS = ("diagnostic", "remediation", "rag")


def background(
    rng: random.Random,
    *,
    runs_per_agent: int,
    escalation_rate: float,
    t0: float,
    tag: str,
    spacing: float = 120.0,
) -> list[Event]:
    """Interleaved clean traffic from all agents."""
    events: list[Event] = []
    for agent in AGENTS:
        for index in range(runs_per_agent):
            start = t0 + index * spacing + rng.uniform(0, spacing / 2)
            escalated = rng.random() < escalation_rate
            events += clean_run(agent, f"{tag}-{agent}-{index:03d}", start, rng, escalated)
    return events
