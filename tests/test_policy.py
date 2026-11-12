import json
from pathlib import Path

import pytest

from agentmon.evaluation.traffic import REFERENCE_POLICY
from agentmon.policy import PolicyError, load_policy, policy_from_dict


def agents(**cfg):
    return {"agents": {"a": {"allowed_tools": ["t"], **cfg}}}


def test_example_policy_is_the_reference_policy():
    example = Path(__file__).parents[1] / "examples" / "policy.json"
    assert json.loads(example.read_text()) == REFERENCE_POLICY
    assert load_policy(example).agents["remediation"].require_approval_for == {"kubectl_patch"}


def test_deployed_policy_matches_the_example():
    root = Path(__file__).parents[1]
    deployed = root / "deploy" / "kubernetes" / "policy.json"
    assert json.loads(deployed.read_text()) == json.loads(
        (root / "examples" / "policy.json").read_text()
    )


def test_typo_is_reported_with_a_suggestion():
    with pytest.raises(PolicyError, match=r"did you mean 'allowed_tools'\?"):
        policy_from_dict({"agents": {"a": {"allowed_tool": ["x"]}}})


def test_allowed_tools_is_required():
    with pytest.raises(PolicyError, match="allowed_tools is required"):
        policy_from_dict({"agents": {"a": {}}})


def test_approval_gate_must_be_an_allowed_tool():
    with pytest.raises(PolicyError, match="not allowed"):
        policy_from_dict(agents(require_approval_for=["other"]))


@pytest.mark.parametrize(
    ("cfg", "message"),
    [
        ({"max_identical_calls": 0}, "positive"),
        ({"max_identical_calls": 2.5}, "integer"),
        ({"max_tokens_per_run": -5}, "positive"),
        ({"max_cost_per_run": "1"}, "number"),
        ({"require_citations": "yes"}, "true or false"),
        ({"allowed_tools": "t"}, "list of tool names"),
    ],
)
def test_values_are_type_checked(cfg, message):
    with pytest.raises(PolicyError, match=message):
        policy_from_dict(agents(**cfg))


def test_limits_can_be_disabled_with_null():
    policy = policy_from_dict(agents(max_tokens_per_run=None))
    assert policy.agents["a"].max_tokens_per_run is None


@pytest.mark.parametrize(
    ("drift", "message"),
    [
        ({"significance": 1.5}, "between 0 and 1"),
        ({"min_runs": 1}, "at least 2"),
        ({"window_runs": 5, "min_runs": 10}, "at least drift.min_runs"),
        ({"windowruns": 5}, "did you mean 'window_runs'"),
    ],
)
def test_drift_settings_are_validated(drift, message):
    with pytest.raises(PolicyError, match=message):
        policy_from_dict({**agents(), "drift": drift})


def test_empty_or_malformed_policy(tmp_path):
    with pytest.raises(PolicyError, match="nonempty"):
        policy_from_dict({"agents": {}})
    with pytest.raises(PolicyError, match="unknown key 'agent'"):
        policy_from_dict({"agent": {}})
    path = tmp_path / "p.json"
    path.write_text("{")
    with pytest.raises(PolicyError, match="invalid JSON"):
        load_policy(path)
