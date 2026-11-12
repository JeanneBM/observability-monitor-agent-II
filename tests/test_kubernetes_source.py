import json
import stat
import urllib.request
from collections import Counter

import pytest

from agentmon.collect.base import Ingestor
from agentmon.collect.kubernetes import (
    InClusterTransport,
    KubectlTransport,
    KubeError,
    KubernetesSource,
    KubernetesSourceConfig,
    guard,
)
from agentmon.store import Store

from .conftest import NOW, record

RECENT_EXIT = "2027-01-15T07:59:00Z"  # NOW - 60s


def pod(
    name, agent, containers=("agent",), *, label="role", ready=True, restarts=None, phase="Running"
):
    restarts = restarts or {}
    return {
        "metadata": {"name": name, "labels": {label: agent} if agent else {}},
        "spec": {"containers": [{"name": c} for c in containers]},
        "status": {
            "phase": phase,
            "containerStatuses": [
                {
                    "name": c,
                    "ready": ready,
                    "restartCount": 1 if c in restarts else 0,
                    "lastState": {"terminated": {"finishedAt": restarts[c]}}
                    if c in restarts
                    else {},
                }
                for c in containers
            ],
        },
    }


def envelope(**values):
    return json.dumps({"agent_monitor_event": record(**values)})


class FakeTransport:
    def __init__(self, pods, logs=None, errors=None):
        self.pods = pods
        self.logs = logs or {}
        self.errors = errors or {}
        self.calls = []

    def get(self, path, params, max_bytes):
        guard(path)
        self.calls.append((path, dict(params)))
        if path.endswith("/pods"):
            if "list" in self.errors:
                raise KubeError(self.errors["list"])
            return json.dumps({"items": self.pods}).encode()
        pod_name = path.split("/")[-2]
        key = (pod_name, params["container"], params.get("previous") == "true")
        if key in self.errors:
            raise KubeError(self.errors[key])
        return self.logs.get(key, "").encode()[: max_bytes + 1]


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "state.sqlite") as s:
        yield s


def config(**kw):
    base = {
        "name": "aks",
        "namespace": "agentic-ops",
        "selector": "app=agentic-ops",
        "agent_label": "role",
    }
    base.update(kw)
    return KubernetesSourceConfig(**base)


def collect(src, store, now=NOW):
    return src.collect(Ingestor(store, now=now, max_age_seconds=86_400))


def test_reads_envelopes_and_ignores_ordinary_logs(store):
    logs = {
        ("diag-1", "agent", False): 'starting up\n{"level":"info"}\n'
        + envelope(agent="diagnostic", id="d1")
        + "\n",
        ("rem-1", "agent", False): envelope(agent="remediation", id="r1") + "\n",
    }
    transport = FakeTransport([pod("diag-1", "diagnostic"), pod("rem-1", "remediation")], logs)
    report = collect(KubernetesSource(config(), transport), store)
    assert (report.status, report.new_events, report.problems) == ("watching", 2, [])
    assert report.details["agents"] == ["diagnostic", "remediation"]
    assert transport.calls[0] == (
        "/api/v1/namespaces/agentic-ops/pods",
        {"labelSelector": "app=agentic-ops"},
    )


def test_selector_and_label_are_configurable(store):
    transport = FakeTransport(
        [pod("p", "rag", label="app.kubernetes.io/component"), pod("q", None)]
    )
    src = KubernetesSource(
        config(selector="", agent_label="app.kubernetes.io/component"), transport
    )
    report = collect(src, store)
    assert report.details["agents"] == ["rag"]
    assert report.details["ignoredPods"] == 1
    assert transport.calls[0][1] == {}


def test_a_pod_cannot_speak_for_another_agent(store):
    transport = FakeTransport(
        [pod("p", "diagnostic")], {("p", "agent", False): envelope(agent="remediation")}
    )
    report = collect(KubernetesSource(config(), transport), store)
    assert [p.rule for p in report.problems] == ["source_identity_mismatch"]
    assert store.count_events() == 0


def test_previous_logs_only_for_the_restarted_container(store):
    restarted = pod("p", "diagnostic", ("agent", "sidecar"), restarts={"agent": RECENT_EXIT})
    transport = FakeTransport([restarted])
    collect(KubernetesSource(config(), transport), store)
    fetched = {(c[1]["container"], c[1].get("previous")) for c in transport.calls[1:]}
    assert fetched == {("agent", None), ("agent", "true"), ("sidecar", None)}


def test_vanished_previous_instance_is_not_an_error(store):
    restarted = pod("p", "diagnostic", restarts={"agent": RECENT_EXIT})
    transport = FakeTransport([restarted], errors={("p", "agent", True): "bad_request"})
    report = collect(KubernetesSource(config(), transport), store)
    assert report.status == "watching"


def test_one_failing_pod_degrades_but_does_not_blind_the_source(store):
    transport = FakeTransport(
        [pod("a", "diagnostic"), pod("b", "remediation")],
        {("b", "agent", False): envelope(agent="remediation", id="ok")},
        errors={("a", "agent", False): "forbidden"},
    )
    src = KubernetesSource(config(), transport)
    report = collect(src, store)
    assert report.status == "degraded"
    assert [(p.rule, p.subject) for p in report.problems] == [
        ("collection_error", "agent:diagnostic:forbidden")
    ]
    assert report.new_events == 1
    cursors = store.cursor("aks")["containers"]
    assert cursors["b/agent"] == NOW
    assert cursors["a/agent"] < NOW  # the failed window is retried next cycle


def test_cursor_advances_per_container_with_overlap(store):
    transport = FakeTransport([pod("p", "diagnostic")])
    src = KubernetesSource(config(overlap_seconds=30, initial_lookback_seconds=600), transport)
    collect(src, store, now=NOW)
    collect(src, store, now=NOW + 5)
    first, second = (c[1]["sinceTime"] for c in transport.calls if c[0].endswith("/log"))
    assert first == "2027-01-15T07:49:30Z"  # NOW - 600 - 30
    assert second == "2027-01-15T07:59:30Z"  # NOW - 30


def test_two_sources_keep_independent_cursors(store):
    a = KubernetesSource(config(name="a"), FakeTransport([pod("p", "diagnostic")]))
    b = KubernetesSource(config(name="b"), FakeTransport([pod("q", "rag")]))
    collect(a, store, now=NOW)
    collect(b, store, now=NOW + 100)
    assert store.cursor("a")["containers"] == {"p/agent": NOW}
    assert store.cursor("b")["containers"] == {"q/agent": NOW + 100}


def test_missing_and_unhealthy_agents(store):
    transport = FakeTransport([pod("p", "diagnostic", ready=False)])
    src = KubernetesSource(
        config(expected_agents=frozenset({"diagnostic", "remediation"})), transport
    )
    report = collect(src, store)
    assert Counter(p.rule for p in report.problems) == {"agent_unhealthy": 1, "agent_missing": 1}
    assert report.status == "degraded"


def test_list_failure_makes_the_source_unavailable(store):
    report = collect(
        KubernetesSource(config(), FakeTransport([], errors={"list": "unauthorized"})), store
    )
    assert (report.status, report.details["error"]) == ("unavailable", "unauthorized")


def test_truncated_read_is_reported(store):
    big = (envelope(agent="diagnostic") + "\n") * 50
    transport = FakeTransport([pod("p", "diagnostic")], {("p", "agent", False): big})
    report = collect(KubernetesSource(config(max_log_bytes=500), transport), store)
    assert "collection_truncated" in {p.rule for p in report.problems}


def test_credential_expiry(store):
    src = KubernetesSource(
        config(credential_expires_at=NOW + 3600), FakeTransport([pod("p", "rag")])
    )
    assert [p.rule for p in collect(src, store).problems] == ["credential_expiring"]
    expired = KubernetesSource(config(credential_expires_at=NOW - 1), FakeTransport([]))
    assert collect(expired, store).details["error"] == "credential_expired"


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/namespaces/agentic-ops/pods/p/exec",
        "/api/v1/namespaces/agentic-ops/secrets",
        "/apis/apps/v1/namespaces/agentic-ops/deployments/x",
        "/api/v1/namespaces/agentic-ops/pods/../secrets",
        "/api/v1/namespaces/agentic-ops/pods/p/log/../../../secrets",
    ],
)
def test_guard_refuses_everything_but_pod_reads(path):
    with pytest.raises(KubeError, match="path_not_allowed"):
        guard(path)


def fake_kubectl(tmp_path, stdout="", stderr="", code=0):
    script = tmp_path / "kubectl"
    log = tmp_path / "argv.json"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"open({str(log)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
        f"sys.stdout.write({stdout!r}); sys.stderr.write({stderr!r}); sys.exit({code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script), log


def test_kubectl_transport_issues_a_raw_get(tmp_path):
    kubectl, log = fake_kubectl(tmp_path, stdout='{"items": []}')
    transport = KubectlTransport("ro.yaml", "lab", kubectl=kubectl)
    body = transport.get("/api/v1/namespaces/ns/pods", {"labelSelector": "app=x"}, 1000)
    assert json.loads(body) == {"items": []}
    argv = json.loads(log.read_text())
    assert argv[:4] == ["--kubeconfig", "ro.yaml", "--context", "lab"]
    assert argv[4:7] == ["get", "--raw", "/api/v1/namespaces/ns/pods?labelSelector=app%3Dx"]


@pytest.mark.parametrize(
    ("stderr", "code"),
    [
        ("Error from server (Forbidden): pods is forbidden", "forbidden"),
        ("error: You must be logged in (Unauthorized)", "unauthorized"),
        ('Error from server (NotFound): pods "x" not found', "not_found"),
        ("something else", "request_failed"),
    ],
)
def test_kubectl_errors_are_classified_without_their_text(tmp_path, stderr, code):
    kubectl, _ = fake_kubectl(tmp_path, stderr=stderr, code=1)
    with pytest.raises(KubeError) as info:
        KubectlTransport(None, kubectl=kubectl).get("/api/v1/namespaces/ns/pods", {}, 10)
    assert info.value.code == code


def test_missing_kubectl(tmp_path):
    with pytest.raises(KubeError, match="kubectl_missing"):
        KubectlTransport(None, kubectl=str(tmp_path / "nope")).get(
            "/api/v1/namespaces/n/pods", {}, 1
        )


def test_in_cluster_transport_sends_only_get_with_fresh_token(tmp_path, monkeypatch):
    (tmp_path / "token").write_text("t1\n")
    (tmp_path / "ca.crt").write_text("")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setattr("ssl.create_default_context", lambda cafile: None)
    seen = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n):
            return b'{"items": []}'

    def urlopen(request, timeout, context):
        seen.append((request.get_method(), request.full_url, request.headers["Authorization"]))
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    transport = InClusterTransport(sa_dir=tmp_path)
    transport.get("/api/v1/namespaces/ns/pods", {}, 100)
    (tmp_path / "token").write_text("t2\n")  # projected tokens rotate
    transport.get("/api/v1/namespaces/ns/pods", {}, 100)
    assert seen == [
        ("GET", "https://10.0.0.1:443/api/v1/namespaces/ns/pods", "Bearer t1"),
        ("GET", "https://10.0.0.1:443/api/v1/namespaces/ns/pods", "Bearer t2"),
    ]


def test_in_cluster_transport_outside_a_cluster(monkeypatch):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    with pytest.raises(KubeError, match="not_in_cluster"):
        InClusterTransport()


def test_envelope_written_by_the_reference_emitter_is_collected(store):
    import io

    from agentmon.emitter import LogSink, Telemetry

    stream = io.StringIO()
    with Telemetry("diagnostic", LogSink(stream), clock=lambda: NOW).run("r") as run:
        run.tool("kubectl_get", {"pod": "p"})
    transport = FakeTransport([pod("p", "diagnostic")], {("p", "agent", False): stream.getvalue()})
    assert collect(KubernetesSource(config(), transport), store).new_events == 3
