#!/usr/bin/env python3
"""RetryStorm - Microservice retry/timeout topology analyzer."""
import yaml, json, sys, argparse, functools, operator


def load_topology(path):
    with open(path) as f:
        return yaml.safe_load(f)


def build_graph(topo):
    g = {}
    for svc in topo.get("services", []):
        g[svc["name"]] = [
            {"target": c["target"], "retries": c.get("retries", 0),
             "timeout_ms": c.get("timeout_ms", 5000),
             "circuit_breaker": c.get("circuit_breaker", False)}
            for c in svc.get("calls", [])
        ]
    return g


def entry_points(graph):
    targets = {c["target"] for calls in graph.values() for c in calls}
    entries = [s for s in graph if s not in targets]
    return entries or list(graph.keys())[:1]


def find_paths(graph, node, visited=None):
    visited = (visited or set()) | {node}
    calls = graph.get(node, [])
    if not calls:
        return [[(node, None)]]
    result = []
    for c in calls:
        if c["target"] not in visited:
            for sub in find_paths(graph, c["target"], visited):
                result.append([(node, c)] + sub)
    return result or [[(node, None)]]


def analyze_path(path):
    edges = [(s, c) for s, c in path if c is not None]
    if not edges:
        return {"amplification": 1, "issues": []}
    amp = functools.reduce(operator.mul, (c["retries"] + 1 for _, c in edges), 1)
    issues = []
    if amp > 4:
        sev = "critical" if amp > 50 else "high" if amp > 16 else "warning"
        chain = " -> ".join(s for s, _ in path)
        issues.append({"type": "retry_amplification", "severity": sev,
                        "amplification": amp, "chain": chain})
    for i in range(len(edges) - 1):
        pt = edges[i][1]["timeout_ms"]
        ct, cr = edges[i + 1][1]["timeout_ms"], edges[i + 1][1]["retries"]
        if pt < ct * (cr + 1):
            issues.append({"type": "timeout_mismatch", "severity": "high",
                           "parent": edges[i][0], "child": edges[i + 1][0],
                           "parent_timeout": pt, "needed": ct * (cr + 1)})
    for s, c in edges:
        if not c.get("circuit_breaker") and c["retries"] >= 3:
            issues.append({"type": "no_circuit_breaker", "severity": "warning",
                           "from": s, "to": c["target"], "retries": c["retries"]})
    return {"amplification": amp, "issues": issues}


def analyze(topo):
    graph = build_graph(topo)
    results = []
    for ep in entry_points(graph):
        for path in find_paths(graph, ep):
            chain = " -> ".join(s for s, _ in path)
            info = analyze_path(path)
            results.append({"chain": chain, **info})
    all_issues = [i for r in results for i in r["issues"]]
    crit = sum(1 for i in all_issues if i["severity"] == "critical")
    high = sum(1 for i in all_issues if i["severity"] == "high")
    return {"paths": results, "total_issues": len(all_issues),
            "critical": crit, "high": high, "issues": all_issues}


def to_mermaid(topo):
    graph = build_graph(topo)
    lines = ["graph LR"]
    for svc, calls in graph.items():
        for c in calls:
            lines.append(f"    {svc} -->|retries={c['retries']}| {c['target']}")
    return "\n".join(lines)


def to_sarif(report):
    results = [{"ruleId": i["type"],
                "level": "error" if i["severity"] in ("critical", "high") else "warning",
                "message": {"text": json.dumps(i)}} for i in report["issues"]]
    sarif = {"version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "RetryStorm", "version": "1.0.0"}},
                       "results": results}]}
    return json.dumps(sarif, indent=2)


def format_report(report, fmt="text"):
    if fmt == "json":
        return json.dumps(report, indent=2)
    if fmt == "sarif":
        return to_sarif(report)
    lines = [f"RetryStorm: {report['total_issues']} issues "
             f"({report['critical']} critical, {report['high']} high)", ""]
    for p in report["paths"]:
        flag = "CRITICAL" if any(i["severity"] == "critical" for i in p["issues"]) \
            else "WARN" if p["issues"] else "OK"
        lines.append(f"  [{flag}] {p['chain']}  ({p['amplification']}x)")
        for i in p["issues"]:
            detail = {k: v for k, v in i.items() if k not in ("type", "severity")}
            lines.append(f"      [{i['severity'].upper()}] {i['type']}: {json.dumps(detail)}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="RetryStorm - Retry storm detector")
    ap.add_argument("topology", help="Path to topology YAML file")
    ap.add_argument("-f", "--format", choices=["text", "json", "sarif", "mermaid"], default="text")
    ap.add_argument("--max-amp", type=int, default=0, help="CI gate: fail if amplification exceeds this")
    args = ap.parse_args()
    topo = load_topology(args.topology)
    if args.format == "mermaid":
        print(to_mermaid(topo))
        return
    report = analyze(topo)
    print(format_report(report, args.format))
    if args.max_amp and any(p["amplification"] > args.max_amp for p in report["paths"]):
        sys.exit(1)
    if report["critical"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
