"""agentmon command line."""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .collect.kubernetes import KubeError
from .config import ConfigError, load_config
from .drift import load_baseline, save_baseline
from .engine import analyze, build_baseline
from .evaluation.harness import (
    BACKGROUND_RUNS,
    BASELINE_RUNS,
    T0,
    end_of,
    evaluate,
    format_report,
    scenarios,
)
from .evaluation.traffic import background, reference_policy
from .incidents import IncidentLedger
from .policy import PolicyError, load_policy
from .schema import Severity, TelemetryError, dump_events, load_events
from .store import Store
from .triage import Summarizer, triage


def _analyze(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    baseline = load_baseline(args.baseline) if args.baseline else None
    findings = analyze(load_events(args.events), policy, baseline=baseline, now=args.now)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        summarizer: Summarizer | None = None
        if args.llm:
            from .triage import AzureOpenAISummarizer

            summarizer = AzureOpenAISummarizer()
        print(triage(findings, summarizer))
    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.severity >= threshold for f in findings) else 0


def _baseline(args: argparse.Namespace) -> int:
    baseline = build_baseline(load_events(args.events))
    save_baseline(baseline, args.out)
    print(f"baseline for {len(baseline)} agent(s) written to {args.out}")
    return 0


def _validate(args: argparse.Namespace) -> int:
    if args.policy:
        policy = load_policy(args.policy)
        print(f"policy OK: {len(policy.agents)} agent(s)")
    if args.config:
        config = load_config(args.config)
        load_policy(config.policy)
        if config.baseline:
            load_baseline(config.baseline)
        print(f"config OK: {len(config.sources)} source(s)")
    return 0


def _eval(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy) if args.policy else reference_policy()
    report = evaluate(
        policy,
        tuple(range(1, args.seeds + 1)),
        min_precision=args.min_precision,
        min_recall=args.min_recall,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "passed": report.passed,
                    "seeds": report.seeds,
                    "statisticalRulesJudged": report.statistical_judged,
                    "rules": report.per_rule(),
                    "outcomes": [
                        {
                            "scenario": o.scenario,
                            "seed": o.seed,
                            "passed": o.passed,
                            "missed": sorted(o.missed),
                            "extra": sorted(o.extra),
                        }
                        for o in report.outcomes
                    ],
                },
                indent=2,
            )
        )
    else:
        print(format_report(report))
    return 0 if report.passed else 1


def _generate(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(1)
    policy = reference_policy()
    known_good = background(
        rng, runs_per_agent=BASELINE_RUNS, escalation_rate=0.1, t0=T0 - 86_400, tag="base"
    )
    dump_events(known_good, str(out / "baseline_events.jsonl"))
    save_baseline(build_baseline(known_good), out / "baseline.json")
    for scenario in scenarios():
        case_rng = random.Random(f"1:{scenario.id}")
        clean = background(
            case_rng, runs_per_agent=BACKGROUND_RUNS, escalation_rate=0.1, t0=T0, tag="bg"
        )
        case = scenario.build(case_rng, policy, end_of(clean) + 60)
        events = [e for e in clean if e.agent not in case.replaces] + case.events
        dump_events(sorted(events, key=lambda e: (e.ts, e.id)), str(out / f"{scenario.id}.jsonl"))
    print(f"sample telemetry written to {out}/")
    return 0


def _watch(args: argparse.Namespace) -> int:
    from .worker import watch

    config = load_config(args.config)
    state = args.state or config.state_dir
    if state is None:
        raise ConfigError("pass --state or set stateDir in the config")
    return watch(config, state, interval=args.interval, once=args.once)


def _incidents(args: argparse.Namespace) -> int:
    path = Path(args.state) / "events.sqlite"
    if not path.exists():
        print(f"no state database at {path}", file=sys.stderr)
        return 2
    with Store(path) as store:
        ledger = IncidentLedger(store.db)
        if args.ack is not None:
            try:
                item = ledger.acknowledge(args.ack, args.by, time.time())
            except KeyError:
                print(f"no incident {args.ack}", file=sys.stderr)
                return 2
            store.commit()
            print(json.dumps(item, indent=2))
            return 0
        items = ledger.list(include_resolved=args.all)
    if args.json:
        print(json.dumps(items, indent=2))
        return 0
    if not items:
        print("no incidents")
    for item in items:
        ack = f" ack:{item['acknowledgedBy']}" if item["acknowledgedBy"] else ""
        print(
            f"#{item['id']:<5}{item['status']:<9}{item['severity']:<9}{item['rule']:<24}"
            f"{item['agent']:<20}{item['message']}{ack}"
        )
    return 0


def _health(args: argparse.Namespace) -> int:
    """Exit 0 when health.json is fresh (and ``ok`` with --require-ok). For probes."""
    try:
        health = json.loads((Path(args.state) / "health.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("health report missing or unreadable", file=sys.stderr)
        return 1
    age = time.time() - float(health.get("updatedAt", 0))
    if age > args.max_age:
        print(f"health report is stale ({age:.0f}s old)", file=sys.stderr)
        return 1
    if args.require_ok and health.get("status") != "ok":
        print(f"monitor status is {health.get('status')!r}", file=sys.stderr)
        return 1
    print(f"{health.get('status')} ({age:.0f}s ago, {health.get('events')} events)")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentmon", description="Read-only monitor for AI-agent telemetry."
    )
    p.add_argument("--version", action="version", version=f"agentmon {__version__}")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyse a JSONL telemetry file once")
    a.add_argument("events")
    a.add_argument("--policy", required=True)
    a.add_argument("--baseline")
    a.add_argument("--now", type=float, help="epoch seconds; enables run_stalled")
    a.add_argument("--json", action="store_true", help="machine-readable findings")
    a.add_argument("--llm", action="store_true", help="LLM triage summary (Azure OpenAI)")
    a.add_argument(
        "--fail-on",
        default="high",
        choices=[s.label for s in Severity],
        help="exit 1 if a finding is at least this severe (default: high)",
    )
    a.set_defaults(handler=_analyze)

    b = sub.add_parser("baseline", help="build a drift baseline from known-good telemetry")
    b.add_argument("events")
    b.add_argument("--out", required=True)
    b.set_defaults(handler=_baseline)

    v = sub.add_parser("validate", help="validate a policy and/or a monitor config")
    v.add_argument("--policy")
    v.add_argument("--config")
    v.set_defaults(handler=_validate)

    e = sub.add_parser("eval", help="evaluate the monitor on injected anomalies")
    e.add_argument("--policy", help="defaults to the built-in reference policy")
    e.add_argument("--seeds", type=int, default=20)
    e.add_argument("--min-precision", type=float, default=0.9, help="statistical rules")
    e.add_argument("--min-recall", type=float, default=0.95, help="statistical rules")
    e.add_argument("--json", action="store_true")
    e.set_defaults(handler=_eval)

    g = sub.add_parser("generate", help="write sample telemetry and a baseline")
    g.add_argument("--out", required=True)
    g.set_defaults(handler=_generate)

    w = sub.add_parser("watch", help="observe sources continuously")
    w.add_argument("--config", required=True)
    w.add_argument("--state", help="state directory (overrides stateDir)")
    w.add_argument("--interval", type=float, default=5.0)
    w.add_argument("--once", action="store_true", help="run a single cycle")
    w.set_defaults(handler=_watch)

    i = sub.add_parser("incidents", help="list or acknowledge incidents")
    i.add_argument("--state", required=True)
    i.add_argument("--all", action="store_true", help="include resolved incidents")
    i.add_argument("--json", action="store_true")
    i.add_argument("--ack", type=int, metavar="ID", help="acknowledge an incident")
    i.add_argument("--by", default="operator", help="who acknowledges")
    i.set_defaults(handler=_incidents)

    h = sub.add_parser("health", help="probe: is the monitor alive (and healthy)?")
    h.add_argument("--state", required=True)
    h.add_argument("--max-age", type=float, default=60.0)
    h.add_argument("--require-ok", action="store_true")
    h.set_defaults(handler=_health)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )
    try:
        return int(args.handler(args))
    except (PolicyError, ConfigError, TelemetryError, KubeError, ValueError, OSError) as exc:
        print(f"agentmon: {exc}", file=sys.stderr)
        return 2
