"""Deterministic run-level detection rules.

Every rule is a pure function of one run, the agent's policy and an optional
clock. No rule calls a model or the network, and none mutates its input.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Final

from .policy import AgentPolicy
from .runs import Run
from .schema import Finding, Severity

RunRule = Callable[[Run, AgentPolicy, float | None], list[Finding]]

MAX_EVIDENCE: Final = 5

# Rule catalogue: identifier -> (severity, what it detects). Used by docs and evaluation.
CATALOG: Final[dict[str, tuple[Severity, str]]] = {
    "permission_violation": (Severity.CRITICAL, "tool call outside the agent's allowlist"),
    "unapproved_action": (
        Severity.CRITICAL,
        "approval-gated tool called without a preceding policy_authorized event",
    ),
    "unknown_agent": (Severity.HIGH, "telemetry from an agent with no policy entry"),
    "unverified_claim": (Severity.HIGH, "'fixed' claim in a finished run with no verification"),
    "claim_contradicted": (Severity.HIGH, "'fixed' claim whose verification did not return ok"),
    "ungrounded_answer": (Severity.HIGH, "answer without any retrieval results"),
    "citation_mismatch": (Severity.HIGH, "answer citing nothing, or citing unretrieved sources"),
    "run_failed": (Severity.HIGH, "run finished with status 'error'"),
    "run_stalled": (Severity.HIGH, "run without a terminal event past its idle timeout"),
    "tool_loop": (Severity.MEDIUM, "same tool with the same arguments repeated beyond the limit"),
    "budget_exceeded": (Severity.MEDIUM, "tokens, cost, tool calls or duration above the limit"),
    "behavior_drift": (
        Severity.MEDIUM,
        "escalation rate or tool calls per run significantly above the baseline",
    ),
    "run_integrity": (Severity.LOW, "events recorded after the run's terminal event"),
}


def finding(rule: str, run: Run, subject: str, message: str, evidence: list[str]) -> Finding:
    severity = CATALOG[rule][0]
    return Finding(
        rule, severity, run.agent, run.run_id, subject, message, tuple(evidence[:MAX_EVIDENCE])
    )


def permission_violation(run: Run, policy: AgentPolicy, now: float | None) -> list[Finding]:
    calls: dict[str, list[str]] = {}
    for event in run.of_type("tool_call"):
        tool = event.tool or "?"
        if tool not in policy.allowed_tools:
            calls.setdefault(tool, []).append(event.id)
    return [
        finding(
            "permission_violation",
            run,
            f"tool:{tool}",
            f"tool {tool!r} is outside the allowed set ({len(ids)} call(s))",
            ids,
        )
        for tool, ids in calls.items()
    ]


def unapproved_action(run: Run, policy: AgentPolicy, now: float | None) -> list[Finding]:
    """Each policy_authorized event grants exactly one call of its tool."""
    if not policy.require_approval_for:
        return []
    grants: Counter[str] = Counter()
    denied: set[str] = set()
    offending: dict[str, list[str]] = {}
    for event in run.events:
        tool = event.tool or "?"
        if event.type == "policy_authorized":
            grants[tool] += 1
            denied.discard(tool)
        elif event.type == "policy_denied":
            grants[tool] = 0
            denied.add(tool)
        elif event.type == "tool_call" and tool in policy.require_approval_for:
            if grants[tool] > 0:
                grants[tool] -= 1
            else:
                offending.setdefault(tool, []).append(event.id)
    return [
        finding(
            "unapproved_action",
            run,
            f"tool:{tool}",
            f"{tool!r} called {len(ids)}x "
            + ("after policy_denied" if tool in denied else "without policy_authorized"),
            ids,
        )
        for tool, ids in offending.items()
    ]


def tool_loop(run: Run, policy: AgentPolicy, now: float | None) -> list[Finding]:
    """Calls without args_hash cannot be told apart, so they count as identical."""
    calls: dict[tuple[str, str | None], list[str]] = {}
    for event in run.of_type("tool_call"):
        calls.setdefault((event.tool or "?", event.args_hash), []).append(event.id)
    out = []
    limit = policy.max_identical_calls
    for (tool, digest), ids in calls.items():
        if len(ids) <= limit:
            continue
        detail = "identical arguments" if digest else "no args_hash (treated as identical)"
        out.append(
            finding(
                "tool_loop",
                run,
                f"tool:{tool}:{digest or 'unhashed'}",
                f"{tool!r} called {len(ids)}x with {detail}; limit {limit}",
                ids,
            )
        )
    return out


def budget_exceeded(run: Run, policy: AgentPolicy, now: float | None) -> list[Finding]:
    tokens = sum(e.tokens for e in run.events)
    cost = sum(e.cost_usd for e in run.events)
    calls = len(run.of_type("tool_call"))
    duration = run.last.ts - run.first.ts
    checks: list[tuple[str, float, float | None, str]] = [
        ("tokens", tokens, policy.max_tokens_per_run, f"{tokens} tokens"),
        ("cost", cost, policy.max_cost_per_run, f"${cost:.2f}"),
        ("tool_calls", calls, policy.max_tool_calls_per_run, f"{calls} tool calls"),
        ("duration", duration, policy.max_run_seconds, f"{duration:.0f}s"),
    ]
    return [
        finding(
            "budget_exceeded", run, subject, f"run used {used} (limit {limit:g})", [run.last.id]
        )
        for subject, value, limit, used in checks
        if limit is not None and value > limit
    ]


def claims(run: Run, policy: AgentPolicy, now: float | None) -> list[Finding]:
    """A 'fixed' claim needs a later verification that returned 'ok'.

    With ``attrs.claim_id`` the verification is matched by id. Without it, the
    verifications between this claim and the next claim apply, the last one wins.
    A claim in a run that is still in flight is pending, not a finding.
    """
    if not policy.require_verification:
        return []
    out = []
    terminal = run.terminal is not None
    for index, claim in enumerate(run.events):
        if claim.type != "claim" or claim.status != "fixed":
            continue
        claim_id = claim.attrs.get("claim_id")
        later = run.events[index + 1 :]
        if isinstance(claim_id, str) and claim_id:
            checks = [
                v for v in later if v.type == "verification" and v.attrs.get("claim_id") == claim_id
            ]
        else:
            checks = []
            for event in later:
                if event.type == "claim":
                    break
                if event.type == "verification":
                    checks.append(event)
        subject = f"claim:{claim_id or claim.id}"
        if not checks:
            if terminal:
                out.append(
                    finding(
                        "unverified_claim",
                        run,
                        subject,
                        "agent claimed 'fixed' but the run ended without a verification",
                        [claim.id],
                    )
                )
        elif checks[-1].status != "ok":
            out.append(
                finding(
                    "claim_contradicted",
                    run,
                    subject,
                    f"agent claimed 'fixed' but verification returned {checks[-1].status!r}",
                    [claim.id, checks[-1].id],
                )
            )
    return out


def grounding(run: Run, policy: AgentPolicy, now: float | None) -> list[Finding]:
    """Citation membership; it does not prove that an answer is true."""
    if not policy.require_citations:
        return []
    out = []
    for answer in run.of_type("answer"):
        if answer.status == "abstained" and not answer.citations:
            continue
        subject = f"answer:{answer.id}"
        if not answer.retrieved:
            out.append(
                finding(
                    "ungrounded_answer",
                    run,
                    subject,
                    "answer produced without any retrieval results",
                    [answer.id],
                )
            )
            continue
        retrieved = set(answer.retrieved)
        foreign = [c for c in answer.citations if c not in retrieved]
        if not answer.citations:
            message = "answer has no citations"
        elif foreign:
            message = f"{len(foreign)} citation(s) not in the retrieved set, e.g. {foreign[0]!r}"
        else:
            continue
        out.append(finding("citation_mismatch", run, subject, message, [answer.id]))
    return out


def lifecycle(run: Run, policy: AgentPolicy, now: float | None) -> list[Finding]:
    terminal = run.terminal
    out = []
    if terminal is None:
        idle = None if now is None else now - run.last.ts
        if idle is not None and idle > policy.run_idle_timeout_seconds:
            out.append(
                finding(
                    "run_stalled",
                    run,
                    "idle",
                    f"no terminal event; idle for {idle:.0f}s "
                    f"(timeout {policy.run_idle_timeout_seconds:g}s)",
                    [run.last.id],
                )
            )
        return out
    if terminal.status == "error":
        error = terminal.attrs.get("error_type")
        suffix = f" ({error})" if isinstance(error, str) else ""
        out.append(
            finding(
                "run_failed", run, "terminal", f"run ended with an error{suffix}", [terminal.id]
            )
        )
    late = [e.id for e in run.events if e.ts > terminal.ts]
    if late:
        out.append(
            finding(
                "run_integrity",
                run,
                "after_terminal",
                f"{len(late)} event(s) recorded after run_finished",
                late,
            )
        )
    return out


RUN_RULES: Final[tuple[RunRule, ...]] = (
    permission_violation,
    unapproved_action,
    tool_loop,
    budget_exceeded,
    claims,
    grounding,
    lifecycle,
)
