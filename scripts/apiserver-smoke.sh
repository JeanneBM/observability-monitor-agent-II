#!/usr/bin/env bash
# Integration smoke test against a real kube-apiserver (envtest binaries, no Docker).
#
#   ENVTEST_BIN=/path/to/envtest/bin scripts/apiserver-smoke.sh
#
# Verifies on a live API server:
#   1. deploy/kubernetes renders and is accepted by the API server;
#   2. the monitor's ServiceAccount can list pods and read pod logs in the agents'
#      namespace, and nothing else (no create/patch/delete/exec/secrets, no other ns);
#   3. the kubectl transport, authenticated with that ServiceAccount's token, lists the
#      selected agent pods, ignores unrelated pods and reports a forbidden namespace
#      as source_unavailable/forbidden;
#   4. the in-cluster transport verifies TLS against the cluster CA, authenticates
#      with the projected token, and refuses non-pod paths before sending anything.
# Pods never start (no kubelet), so log collection itself is covered by the kind smoke.
set -euo pipefail

BIN=${ENVTEST_BIN:?set ENVTEST_BIN to a directory with etcd, kube-apiserver and kubectl}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PIDS=()
cleanup() { for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

openssl genrsa -out "$WORK/sa.key" 2048 2>/dev/null
openssl rsa -in "$WORK/sa.key" -pubout -out "$WORK/sa.pub" 2>/dev/null
echo "smoke-admin-token,admin,admin,system:masters" > "$WORK/tokens.csv"

"$BIN/etcd" --data-dir "$WORK/etcd" --listen-client-urls http://127.0.0.1:2379 \
  --advertise-client-urls http://127.0.0.1:2379 --listen-peer-urls http://127.0.0.1:2380 \
  > "$WORK/etcd.log" 2>&1 &
PIDS+=($!)
"$BIN/kube-apiserver" --etcd-servers=http://127.0.0.1:2379 --secure-port=6443 \
  --bind-address=127.0.0.1 --cert-dir="$WORK/certs" --token-auth-file="$WORK/tokens.csv" \
  --authorization-mode=RBAC --service-cluster-ip-range=10.0.0.0/24 \
  --service-account-issuer=https://kubernetes.default.svc \
  --service-account-key-file="$WORK/sa.pub" --service-account-signing-key-file="$WORK/sa.key" \
  --disable-admission-plugins=ServiceAccount > "$WORK/apiserver.log" 2>&1 &
PIDS+=($!)

kubeconfig() {  # name token
  cat > "$WORK/$1.kubeconfig" <<KUBE
apiVersion: v1
kind: Config
clusters: [{name: smoke, cluster: {server: "https://127.0.0.1:6443", insecure-skip-tls-verify: true}}]
users: [{name: $1, user: {token: "$2"}}]
contexts: [{name: smoke, context: {cluster: smoke, user: $1}}]
current-context: smoke
KUBE
}
kubeconfig admin smoke-admin-token
K=("$BIN/kubectl" --kubeconfig "$WORK/admin.kubeconfig")

for _ in $(seq 1 60); do
  "${K[@]}" get --raw /readyz >/dev/null 2>&1 && break
  sleep 1
done
"${K[@]}" get --raw /readyz >/dev/null

echo "== 1. manifests"
"${K[@]}" create namespace agentic-ops
"${K[@]}" kustomize "$ROOT/deploy/kubernetes" | "${K[@]}" apply -f -
for role in diagnostic remediation; do
  "${K[@]}" -n agentic-ops run "$role-0" --image=busybox --restart=Never \
    --labels="app=agentic-ops,role=$role" >/dev/null
done
"${K[@]}" -n agentic-ops run unrelated --image=busybox --restart=Never --labels=app=other >/dev/null

echo "== 2. RBAC of system:serviceaccount:agentmon:agentmon"
SA=system:serviceaccount:agentmon:agentmon
expect() {  # expected verb resource namespace
  local got
  got=$("${K[@]}" auth can-i "$2" "$3" -n "$4" --as="$SA" 2>/dev/null || true)
  printf '  %-4s %-8s %-18s %-12s %s\n' "$got" "$2" "$3" "$4" "$([ "$got" = "$1" ] && echo ok || echo FAIL)"
  [ "$got" = "$1" ]
}
expect yes list pods agentic-ops
expect yes get pods agentic-ops
expect yes get pods/log agentic-ops
expect no create pods agentic-ops
expect no patch pods agentic-ops
expect no delete pods agentic-ops
expect no create pods/exec agentic-ops
expect no patch deployments agentic-ops
expect no get secrets agentic-ops
expect no list pods kube-system
expect no get configmaps agentmon

echo "== 3. kubectl transport with the ServiceAccount token"
kubeconfig agentmon "$("${K[@]}" -n agentmon create token agentmon --duration=10m)"
cp "$ROOT/examples/policy.json" "$WORK/policy.json"
cat > "$WORK/sources.json" <<JSON
{"instance": "apiserver-smoke", "policy": "policy.json", "sources": [
  {"type": "kubernetes", "name": "aks", "namespace": "agentic-ops", "selector": "app=agentic-ops",
   "agentLabel": "role", "expectedAgents": ["diagnostic", "remediation"],
   "kubeconfig": "agentmon.kubeconfig"},
  {"type": "kubernetes", "name": "other", "namespace": "kube-system",
   "kubeconfig": "agentmon.kubeconfig"}]}
JSON
PATH="$BIN:$PATH" agentmon watch --config "$WORK/sources.json" --state "$WORK/state" --once
python3 - "$WORK/state" <<'PY'
import json, sys
from pathlib import Path
state = Path(sys.argv[1])
sources = json.loads((state / "health.json").read_text())["sources"]
aks, other = sources["aks"], sources["other"]
assert aks["agents"] == ["diagnostic", "remediation"], aks
assert aks["pods"] == 2 and aks["ignoredPods"] == 0, aks  # selector excluded the unrelated pod
assert other["status"] == "unavailable" and other["error"] == "forbidden", other
rules = {f["rule"] for f in json.loads((state / "findings.json").read_text())}
assert rules == {"agent_unhealthy", "source_unavailable"}, rules  # pods are Pending here
print("  selector, identity labels and forbidden namespace: ok")
PY

echo "== 4. in-cluster transport (TLS + projected token)"
mkdir -p "$WORK/sa"
"${K[@]}" -n agentmon create token agentmon --duration=10m > "$WORK/sa/token"
cp "$WORK/certs/apiserver.crt" "$WORK/sa/ca.crt"
env -u HTTPS_PROXY -u https_proxy KUBERNETES_SERVICE_HOST=127.0.0.1 KUBERNETES_SERVICE_PORT=6443 \
  python3 - "$WORK/sa" <<'PY'
import json, sys
from pathlib import Path
from agentmon.collect.kubernetes import InClusterTransport, KubeError
transport = InClusterTransport(sa_dir=Path(sys.argv[1]))
body = transport.get("/api/v1/namespaces/agentic-ops/pods", {"labelSelector": "app=agentic-ops"}, 1 << 20)
names = sorted(p["metadata"]["name"] for p in json.loads(body)["items"])
assert names == ["diagnostic-0", "remediation-0"], names
for path, code in [("/api/v1/namespaces/kube-system/pods", "forbidden"),
                   ("/api/v1/namespaces/agentic-ops/secrets", "path_not_allowed"),
                   ("/api/v1/namespaces/agentic-ops/pods/diagnostic-0/exec", "path_not_allowed")]:
    try:
        transport.get(path, {}, 100)
    except KubeError as exc:
        assert exc.code == code, (path, exc.code)
    else:
        raise AssertionError(f"{path} was allowed")
print("  list with verified TLS, RBAC denial and local path guard: ok")
PY
echo "PASS"
