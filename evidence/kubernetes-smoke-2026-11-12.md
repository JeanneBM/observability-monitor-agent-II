# Kubernetes smoke tests — 2026-11-12

Verdict: **PASS**. Same script as the CI `kubernetes` job:
`ENVTEST_BIN=… scripts/apiserver-smoke.sh`.

- kube-apiserver and etcd v1.34.1 from the envtest release binaries, RBAC authorization,
  ServiceAccount tokens issued through the TokenRequest API. No kubelet, so pods stay
  Pending; real pod-log collection is covered by the kind smoke workflow.
- Python 3.13, agentmon 0.1.0 from this repository.

## 1. Manifests

`kubectl kustomize deploy/kubernetes | kubectl apply -f -` created all 8 objects (namespace
with Pod Security `restricted`, ServiceAccount, Role, RoleBinding, ConfigMap, PVC,
NetworkPolicy, Deployment). kubeconform `-strict` against Kubernetes 1.34: 8 valid.

## 2. RBAC of `system:serviceaccount:agentmon:agentmon`

| Verb | Resource | Namespace | Allowed |
|---|---|---|---|
| list | pods | agentic-ops | yes |
| get | pods | agentic-ops | yes |
| get | pods/log | agentic-ops | yes |
| create, patch, delete | pods | agentic-ops | no |
| create | pods/exec | agentic-ops | no |
| patch | deployments | agentic-ops | no |
| get | secrets | agentic-ops | no |
| list | pods | kube-system | no |
| get | configmaps | agentmon | no |

## 3. kubectl transport with the ServiceAccount token

Two agent pods (`role=diagnostic`, `role=remediation`, `app=agentic-ops`) and one unrelated
pod (`app=other`). One `watch --once` cycle with two sources:

- `aks` (selector `app=agentic-ops`, `agentLabel: role`): agents `diagnostic` and
  `remediation`, 2 pods, 0 ignored (the selector excluded the unrelated pod), status
  `degraded` with `agent_unhealthy` for both, because the pods are Pending;
- `other` (namespace `kube-system`): `unavailable`, error `forbidden`, incident
  `source_unavailable`.

## 4. In-cluster transport

With `KUBERNETES_SERVICE_HOST=127.0.0.1`, a projected-style token file and the API server's
CA:

- listing the selected pods over HTTPS with certificate verification: both pods returned;
- `/api/v1/namespaces/kube-system/pods`: `forbidden` (RBAC on the server);
- `/api/v1/namespaces/agentic-ops/secrets` and `.../pods/diagnostic-0/exec`:
  `path_not_allowed`, refused by the client before any request was sent.

For comparison, `kubectl get --raw .../pods/diagnostic-0/exec` with the same token was
denied by the server: `cannot get resource "pods/exec"`.

## Kind smoke (real pod logs) — PASS

[Run 43206471820](https://github.com/JeanneBM/observability-monitor-agent-II/actions/runs/43206471820),
commit `00e74b8`: the image built from this repository, loaded into kind and deployed with
`kubectl apply -k deploy/kubernetes` (Pod Security `restricted`, read-only root filesystem,
projected token, NetworkPolicy). Two fixture agents printed 10 canonical envelopes between
ordinary log lines; the diagnostic one called `kubectl_patch`.

The monitor, using the in-cluster transport, reported source `aks` as `watching` with agents
`diagnostic` and `remediation`, 2 pods, 0 rejected records, and exactly one open incident:
`permission_violation|diagnostic|smoke-1|tool:kubectl_patch`. The remediation agent's run
(approval, patch, claim, verification) produced none.
