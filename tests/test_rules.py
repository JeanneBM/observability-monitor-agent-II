from agentmon.engine import analyze
from agentmon.schema import Severity

from .conftest import NOW, builder, make_policy


def keys(events, policy, **kw):
    return {f.key for f in analyze(events, policy, **kw)}


def rules(events, policy, **kw):
    return {f.rule for f in analyze(events, policy, **kw)}


# permissions and approvals -------------------------------------------------


def test_permission_violation_is_one_finding_per_tool(policy):
    b = builder("diagnostic", "r").start().tool("kubectl_patch", {"a": 1})
    b.tool("kubectl_patch", {"a": 2}).tool("kubectl_exec", {})
    findings = analyze(b.finish(), policy)
    assert {(f.subject, f.severity) for f in findings} == {
        ("tool:kubectl_patch", Severity.CRITICAL),
        ("tool:kubectl_exec", Severity.CRITICAL),
    }
    patch = next(f for f in findings if f.subject == "tool:kubectl_patch")
    assert len(patch.evidence) == 2


def test_approved_call_is_accepted(policy):
    b = builder("remediation", "r").start().authorized("kubectl_patch").tool("kubectl_patch", {})
    assert "unapproved_action" not in rules(b.claim("c").verify("ok", "c").finish(), policy)


def test_call_without_approval(policy):
    b = builder("remediation", "r").start().tool("kubectl_patch", {}).claim("c").verify("ok", "c")
    assert keys(b.finish(), policy) == {"unapproved_action|remediation|r|tool:kubectl_patch"}


def test_approval_after_the_call_does_not_count(policy):
    b = builder("remediation", "r").start().tool("kubectl_patch", {}).authorized("kubectl_patch")
    assert "unapproved_action" in rules(b.claim("c").verify("ok", "c").finish(), policy)


def test_one_approval_grants_one_call(policy):
    b = builder("remediation", "r").start().authorized("kubectl_patch")
    b.tool("kubectl_patch", {"d": 1}).tool("kubectl_patch", {"d": 2})
    [finding] = analyze(b.claim("c").verify("ok", "c").finish(), policy)
    assert finding.rule == "unapproved_action"
    assert len(finding.evidence) == 1


def test_denial_revokes_earlier_grants(policy):
    b = builder("remediation", "r").start().authorized("kubectl_patch").denied("kubectl_patch")
    b.tool("kubectl_patch", {}).claim("c").verify("ok", "c")
    [finding] = analyze(b.finish(), policy)
    assert "after policy_denied" in finding.message


def test_new_approval_after_denial_is_honoured(policy):
    b = builder("remediation", "r").start().denied("kubectl_patch").authorized("kubectl_patch")
    b.tool("kubectl_patch", {}).claim("c").verify("ok", "c")
    assert analyze(b.finish(), policy) == []


def test_tools_outside_the_gate_need_no_approval(policy):
    b = builder("remediation", "r").start().tool("acr_check", {}).tool("rollout_status", {})
    assert analyze(b.finish(), policy) == []


# loops and budgets -----------------------------------------------------------


def test_tool_loop_boundary(policy):
    limit = policy.agents["diagnostic"].max_identical_calls
    at = builder("diagnostic", "at").start()
    above = builder("diagnostic", "above").start()
    for _ in range(limit):
        at.tool("kubectl_logs", {"p": 1})
        above.tool("kubectl_logs", {"p": 1})
    above.tool("kubectl_logs", {"p": 1})
    assert analyze(at.finish(), policy) == []
    assert rules(above.finish(), policy) == {"tool_loop"}


def test_different_arguments_are_not_a_loop(policy):
    b = builder("diagnostic", "r").start()
    for n in range(10):
        b.tool("kubectl_get", {"pod": n})
    assert analyze(b.finish(), policy) == []


def test_unhashed_calls_cannot_hide_a_loop(policy):
    b = builder("diagnostic", "r").start()
    for _ in range(10):
        b.tool("kubectl_logs", hashed=False)
    [finding] = analyze(b.finish(), policy)
    assert finding.subject == "tool:kubectl_logs:unhashed"
    assert "no args_hash" in finding.message


def test_budget_subjects():
    policy = make_policy(
        rag={
            "max_tokens_per_run": 100,
            "max_cost_per_run": 0.5,
            "max_tool_calls_per_run": 2,
            "max_run_seconds": 1.0,
        }
    )
    b = builder("rag", "r").start()
    b.add("llm_call", tokens=101, cost_usd=0.6)
    b.tool("retrieve", {"q": 1}).tool("retrieve", {"q": 2}).tool("retrieve", {"q": 3})
    b.answer(["d"], ["d"])
    found = {f.subject for f in analyze(b.finish(), policy) if f.rule == "budget_exceeded"}
    assert found == {"tokens", "cost", "tool_calls", "duration"}


def test_budget_exactly_at_limit_is_fine():
    policy = make_policy(rag={"max_tokens_per_run": 100})
    b = builder("rag", "r").start().llm(60).tool("retrieve", {"q": 1}).answer(["d"], ["d"])
    assert analyze(b.llm(40).finish(), policy) == []


# claims ----------------------------------------------------------------------


def test_claim_matched_by_claim_id(policy):
    b = builder("remediation", "r").start().authorized("kubectl_patch").tool("kubectl_patch", {})
    b.claim("c1").verify("failed", "other").verify("ok", "c1")
    assert analyze(b.finish(), policy) == []


def test_claim_without_id_uses_the_verifications_before_the_next_claim(policy):
    b = builder("remediation", "r").start().authorized("kubectl_patch").tool("kubectl_patch", {})
    b.add("claim", status="fixed").add("verification", status="ok")
    b.add("claim", status="fixed").add("verification", status="failed")
    [finding] = analyze(b.finish(), policy)
    assert finding.rule == "claim_contradicted"
    assert finding.subject.startswith("claim:r-")


def test_last_verification_wins(policy):
    b = builder("remediation", "r").start().authorized("kubectl_patch").tool("kubectl_patch", {})
    b.claim("c").verify("ok", "c").verify("failed", "c")
    assert rules(b.finish(), policy) == {"claim_contradicted"}


def test_claim_in_flight_is_pending_not_a_finding(policy):
    b = builder("remediation", "r", NOW - 10).start().authorized("kubectl_patch")
    b.tool("kubectl_patch", {}).claim("c")
    assert analyze(b.events, policy, now=NOW) == []
    assert rules(b.finish(), policy) == {"unverified_claim"}


def test_claims_are_ignored_when_not_required(policy):
    b = builder("diagnostic", "r").start().claim("c")
    assert analyze(b.finish(), policy) == []


# grounding -------------------------------------------------------------------


def test_grounding_cases(policy):
    ok = builder("rag", "ok").start().tool("retrieve", {}).answer(["a"], ["a", "b"]).finish()
    foreign = builder("rag", "f").start().tool("retrieve", {}).answer(["a", "z"], ["a"]).finish()
    none = builder("rag", "n").start().tool("retrieve", {}).answer([], ["a"]).finish()
    blind = builder("rag", "b").start().answer(["a"], []).finish()
    abstain = builder("rag", "x").start().tool("retrieve", {}).answer([], [], abstained=True)
    fake = builder("rag", "y").start().answer(["a"], [], abstained=True).finish()
    found = {
        (f.run_id, f.rule)
        for f in analyze(ok + foreign + none + blind + abstain.finish() + fake, policy)
    }
    assert found == {
        ("f", "citation_mismatch"),
        ("n", "citation_mismatch"),
        ("b", "ungrounded_answer"),
        ("y", "ungrounded_answer"),  # 'abstained' with citations is still an answer
    }


# lifecycle -------------------------------------------------------------------


def test_stalled_run_needs_a_clock(policy):
    events = builder("rag", "r", NOW - 4000).start().tool("retrieve", {}).events
    assert analyze(events, policy) == []
    assert keys(events, policy, now=NOW) == {"run_stalled|rag|r|idle"}
    assert analyze(events, policy, now=events[-1].ts + 599) == []


def test_failed_run_reports_error_type(policy):
    [finding] = analyze(builder("rag", "r").start().finish("error", "Timeout"), policy)
    assert finding.rule == "run_failed"
    assert "Timeout" in finding.message


def test_events_after_terminal_are_low_severity(policy):
    b = builder("rag", "r").start()
    b.finish()
    b.add("llm_call", tokens=1)
    [finding] = analyze(b.events, policy)
    assert (finding.rule, finding.severity) == ("run_integrity", Severity.LOW)


# engine ----------------------------------------------------------------------


def test_unknown_agent_is_one_finding_for_all_its_runs(policy):
    events = []
    for n in range(4):
        events += builder("ghost", f"g{n}").start().finish()
    [finding] = analyze(events, policy)
    assert finding.key == "unknown_agent|ghost|-|policy"
    assert len(finding.evidence) == 4


def test_findings_are_sorted_by_severity(policy):
    events = builder("diagnostic", "r").start().tool("kubectl_patch", {}).finish("error")
    severities = [f.severity for f in analyze(events, policy)]
    assert severities == sorted(severities, reverse=True)
