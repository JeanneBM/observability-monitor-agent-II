"""Kubernetes pod-log source, read-only by construction.

Both transports expose a single ``get`` that issues HTTP GET requests, and both
refuse any path other than listing pods or reading pod logs in the configured
namespace. The collector therefore cannot create, patch, exec or delete, even if
its credential were over-privileged.

Only lines that are JSON objects carrying the envelope key are telemetry. Every
other log line is discarded without being stored.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .base import Ingestor, SourceReport

_NAME = r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?"
READ_ONLY_PATH = re.compile(rf"^/api/v1/namespaces/{_NAME}/pods(/{_NAME}/log)?$")
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class KubeError(Exception):
    """A failed read. ``code`` is a short, persistable reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def guard(path: str) -> str:
    if not READ_ONLY_PATH.fullmatch(path):
        raise KubeError("path_not_allowed")
    return path


class Transport(Protocol):
    def get(self, path: str, params: Mapping[str, str], max_bytes: int) -> bytes: ...


def _classify(stderr: str) -> str:
    for marker, code in (
        ("Forbidden", "forbidden"),
        ("Unauthorized", "unauthorized"),
        ("NotFound", "not_found"),
        ("not found", "not_found"),
        ("BadRequest", "bad_request"),
        ("Timeout", "timeout"),
    ):
        if marker in stderr:
            return code
    return "request_failed"


class KubectlTransport:
    """``kubectl get --raw``: a GET, authenticated by a (scoped) kubeconfig."""

    def __init__(
        self, kubeconfig: str | None, context: str | None = None, kubectl: str = "kubectl"
    ) -> None:
        self.base = [kubectl]
        if kubeconfig:
            self.base += ["--kubeconfig", kubeconfig]
        if context:
            self.base += ["--context", context]

    def get(self, path: str, params: Mapping[str, str], max_bytes: int) -> bytes:
        url = guard(path) + ("?" + urllib.parse.urlencode(params) if params else "")
        argv = [*self.base, "get", "--raw", url, "--request-timeout=10s"]
        try:
            result = subprocess.run(argv, capture_output=True, timeout=20, check=False)  # noqa: S603
        except FileNotFoundError:
            raise KubeError("kubectl_missing") from None
        except subprocess.TimeoutExpired:
            raise KubeError("timeout") from None
        if result.returncode:
            raise KubeError(_classify(result.stderr.decode(errors="replace")))
        return result.stdout[: max_bytes + 1]


class InClusterTransport:
    """Direct HTTPS GET with the pod's projected service-account token."""

    def __init__(self, timeout: float = 10.0, sa_dir: Path = SA_DIR) -> None:
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host:
            raise KubeError("not_in_cluster")
        self.base = f"https://{host}:{port}"
        self.sa_dir = sa_dir
        self.timeout = timeout
        self.context = ssl.create_default_context(cafile=str(sa_dir / "ca.crt"))

    def get(self, path: str, params: Mapping[str, str], max_bytes: int) -> bytes:
        url = self.base + guard(path) + ("?" + urllib.parse.urlencode(params) if params else "")
        token = (self.sa_dir / "token").read_text().strip()  # re-read: projected tokens rotate
        request = urllib.request.Request(  # noqa: S310 - fixed https base URL
            url, method="GET", headers={"Authorization": f"Bearer {token}"}
        )
        try:
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=self.timeout, context=self.context
            ) as response:
                return bytes(response.read(max_bytes + 1))
        except urllib.error.HTTPError as exc:
            codes = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found"}
            raise KubeError(codes.get(exc.code, f"http_{exc.code}")) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise KubeError("unreachable") from None


@dataclass(frozen=True, slots=True)
class KubernetesSourceConfig:
    name: str
    namespace: str
    selector: str = ""
    agent_label: str = "app.kubernetes.io/component"
    expected_agents: frozenset[str] = frozenset()
    containers: frozenset[str] = frozenset()  # empty: every container in the pod spec
    envelope_key: str = "agent_monitor_event"
    overlap_seconds: float = 30.0
    initial_lookback_seconds: float = 600.0
    max_log_bytes: int = 4 * 1024 * 1024
    credential_expires_at: float | None = None


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class KubernetesSource:
    kind = "kubernetes"

    def __init__(self, config: KubernetesSourceConfig, transport: Transport) -> None:
        self.config = config
        self.name = config.name
        self.transport = transport

    def _logs(
        self, pod: str, container: str, since: float, *, previous: bool
    ) -> tuple[bytes, bool]:
        cfg = self.config
        params = {
            "container": container,
            "sinceTime": _iso(since),
            "limitBytes": str(cfg.max_log_bytes),
        }
        if previous:
            params["previous"] = "true"
        path = f"/api/v1/namespaces/{cfg.namespace}/pods/{pod}/log"
        data = self.transport.get(path, params, cfg.max_log_bytes)
        return data, len(data) >= cfg.max_log_bytes

    def _parse(
        self,
        data: bytes,
        agent: str,
        ingestor: Ingestor,
        report: SourceReport,
        rejections: Counter[str],
    ) -> None:
        key = self.config.envelope_key
        for line in data.splitlines():
            if not line.startswith(b"{"):
                continue
            try:
                envelope = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue  # ordinary application log line, or a truncated tail
            if isinstance(envelope, dict) and key in envelope:
                ingestor.ingest(envelope[key], report, {agent}, rejections)

    def collect(self, ingestor: Ingestor) -> SourceReport:
        cfg = self.config
        now = ingestor.now
        report = SourceReport(self.name, self.kind, details={"namespace": cfg.namespace})
        if cfg.credential_expires_at is not None:
            if now >= cfg.credential_expires_at:
                return report.unavailable("credential_expired", "collector credential expired")
            if cfg.credential_expires_at - now < 86_400:
                report.problem(
                    "credential_expiring", "credential", "collector credential expires within 24h"
                )

        params = {"labelSelector": cfg.selector} if cfg.selector else {}
        try:
            raw = self.transport.get(f"/api/v1/namespaces/{cfg.namespace}/pods", params, 32 << 20)
            pods = json.loads(raw)["items"]
            if not isinstance(pods, list):
                raise TypeError
        except KubeError as exc:
            return report.unavailable(exc.code, "pods cannot be listed")
        except (ValueError, KeyError, TypeError):
            return report.unavailable("bad_response", "pod list could not be parsed")

        state = ingestor.store.cursor(self.name)
        old_cursors: dict[str, float] = state.get("containers", {})
        cursors: dict[str, float] = {}
        rejections: Counter[str] = Counter()
        agents: set[str] = set()
        ignored = 0
        for pod in pods:
            meta = pod.get("metadata") or {}
            agent = (meta.get("labels") or {}).get(cfg.agent_label)
            pod_name = meta.get("name")
            if not isinstance(agent, str) or not agent or not isinstance(pod_name, str):
                ignored += 1
                continue
            agents.add(agent)
            status = pod.get("status") or {}
            container_status = {
                s.get("name"): s
                for s in status.get("containerStatuses") or []
                if isinstance(s, dict)
            }
            ready = (
                status.get("phase") == "Running"
                and container_status
                and all(s.get("ready") for s in container_status.values())
            )
            if not ready:
                report.problem(
                    "agent_unhealthy", f"agent:{agent}", f"a pod of {agent!r} is not ready"
                )
            names = [
                c.get("name")
                for c in (pod.get("spec") or {}).get("containers") or []
                if isinstance(c, dict) and (not cfg.containers or c.get("name") in cfg.containers)
            ]
            for container in names:
                if not isinstance(container, str):
                    continue
                cursor_key = f"{pod_name}/{container}"
                since = old_cursors.get(cursor_key, now - cfg.initial_lookback_seconds)
                window = since - cfg.overlap_seconds
                fetches = [False]
                info = container_status.get(container) or {}
                finished = parse_time(
                    ((info.get("lastState") or {}).get("terminated") or {}).get("finishedAt")
                )
                if info.get("restartCount", 0) and finished is not None and finished >= window:
                    fetches.append(True)  # the previous instance of *this* container only
                try:
                    for previous in fetches:
                        try:
                            data, truncated = self._logs(
                                pod_name, container, window, previous=previous
                            )
                        except KubeError as exc:
                            if previous and exc.code in {"bad_request", "not_found"}:
                                continue  # previous instance already garbage-collected
                            raise
                        if truncated:
                            report.problem(
                                "collection_truncated",
                                f"agent:{agent}",
                                f"log read for {agent!r} hit {cfg.max_log_bytes} bytes",
                            )
                        self._parse(data, agent, ingestor, report, rejections)
                except KubeError as exc:
                    report.problem(
                        "collection_error",
                        f"agent:{agent}:{exc.code}",
                        f"logs of {agent!r} could not be read ({exc.code})",
                    )
                    cursors[cursor_key] = since  # retry the same window next cycle
                    continue
                cursors[cursor_key] = now

        for missing in sorted(cfg.expected_agents - agents):
            report.problem("agent_missing", f"agent:{missing}", f"no pod found for {missing!r}")
        Ingestor.flush_rejections(report, rejections)
        ingestor.store.set_cursor(self.name, {"containers": cursors})
        report.details.update(
            {"agents": sorted(agents), "pods": len(pods) - ignored, "ignoredPods": ignored}
        )
        return report
