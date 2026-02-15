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
        ct = edges[i + 1][1]["timeout_ms"]
        child_total = ct * (edges[i + 1][1]["retries"] + 1)
        if pt < child_total:
            issues.append({
                "type": "timeout_mismatch", "severity": "high",
                "parent": edges[i][0], "child": edges[i + 1][0],
                "parent_timeout_ms": pt, "child_worst_case_ms": child_total
            })
    for src, c in edges:
        if not c["circuit_breaker"] and c["retries"] >= 3:
            issues.append({
                "type": "missing_circuit_breaker", "severity": "warning",
                "source": src, "target": c["target"], "retries": c["retries"]
            })
    return {"amplification": amp, "issues": issues}


def analyze(topo):
    graph = build_graph(topo)
    entries = entry_points(graph)
    all_paths = []
    for ep in entries:
        all_paths.extend(find_paths(graph, ep))
    results = []
    total_issues = 0
    critical = 0
    for p in all_paths:
        a = analyze_path(p)
        chain = " -> ".join(s for s, _ in p)
        for issue in a["issues"]:
            if issue.get("severity") == "critical":
                critical += 1
        total_issues += len(a["issues"])
        results.append({
            "chain": chain,
            "amplification": a["amplification"],
            "issues": a["issues"]
        })
    return {
        "paths": results,
        "total_issues": total_issues,
        "critical": critical,
        "max_amplification": max((r["amplification"] for r in results), default=1)
    }


def to_mermaid(topo):
    graph = build_graph(topo)
    lines = ["graph LR"]
    for src, calls in graph.items():
        for c in calls:
            label = f"retries={c['retries']}"
            if c["circuit_breaker"]:
                label += " CB"
            lines.append(f"    {src} -->|{label}| {c['target']}")
    return "\n".join(lines)


def format_json(report):
    """Format report as structured JSON with chains[] and summary{}."""
    chains = []
    for p in report["paths"]:
        chains.append({
            "chain": p["chain"],
            "amplification": p["amplification"],
            "issues": p["issues"]
        })
    output = {
        "chains": chains,
        "summary": {
            "total_chains": len(chains),
            "max_multiplier": report["max_amplification"],
            "critical_count": report["critical"]
        }
    }
    return json.dumps(output, indent=2)


def _sarif_level(severity):
    """Map RetryStorm severity to SARIF level."""
    mapping = {"critical": "error", "high": "error", "warning": "warning"}
    return mapping.get(severity, "note")


def to_sarif(report):
    """Format report as SARIF 2.1.0 for GitHub Advanced Security / Code Scanning."""
    rule_defs = {
        "retry_amplification": {
            "id": "retrystorm-001",
            "name": "RetryAmplification",
            "shortDescription": {"text": "Retry amplification exceeds safe threshold"},
            "helpUri": "https://github.com/retrystorm/retrystorm#retry-amplification",
            "defaultConfiguration": {"level": "error"}
        },
        "timeout_mismatch": {
            "id": "retrystorm-002",
            "name": "TimeoutMismatch",
            "shortDescription": {"text": "Parent timeout shorter than child worst-case duration"},
            "helpUri": "https://github.com/retrystorm/retrystorm#timeout-mismatch",
            "defaultConfiguration": {"level": "error"}
        },
        "missing_circuit_breaker": {
            "id": "retrystorm-003",
            "name": "MissingCircuitBreaker",
            "shortDescription": {"text": "High-retry edge without circuit breaker protection"},
            "helpUri": "https://github.com/retrystorm/retrystorm#circuit-breaker",
            "defaultConfiguration": {"level": "warning"}
        }
    }

    results = []
    rules_seen = set()
    rules = []

    for p in report["paths"]:
        for issue in p["issues"]:
            itype = issue["type"]
            rule_def = rule_defs.get(itype, {
                "id": "retrystorm-000", "name": itype,
                "shortDescription": {"text": itype},
                "defaultConfiguration": {"level": "note"}
            })
            rule_id = rule_def["id"]
            if rule_id not in rules_seen:
                rules_seen.add(rule_id)
                rules.append(rule_def)

            # Build message text
            msg_parts = [issue["type"]]
            if "amplification" in issue:
                msg_parts.append(f"amplification={issue['amplification']}x")
            if "chain" in issue:
                msg_parts.append(f"chain: {issue['chain']}")
            if "parent" in issue:
                msg_parts.append(
                    f"{issue['parent']} timeout {issue['parent_timeout_ms']}ms "
                    f"< {issue['child']} worst case {issue['child_worst_case_ms']}ms"
                )
            if "source" in issue and "target" in issue:
                msg_parts.append(f"{issue['source']} -> {issue['target']}")

            result = {
                "ruleId": rule_id,
                "level": _sarif_level(issue.get("severity", "warning")),
                "message": {"text": ", ".join(msg_parts)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "topology.yaml"},
                        "region": {"startLine": 1}
                    }
                }]
            }
            results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RetryStorm",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/retrystorm/retrystorm",
                    "rules": sorted(rules, key=lambda r: r["id"])
                }
            },
            "results": results
        }]
    }
    return json.dumps(sarif, indent=2)


def format_text(report):
    """Format report as human-readable text."""
    lines = []
    lines.append("=" * 60)
    lines.append("RetryStorm Analysis Report")
    lines.append("=" * 60)
    for p in report["paths"]:
        amp = p["amplification"]
        marker = " \u26a0\ufe0f" if amp > 4 else ""
        lines.append(f"\n  Chain: {p['chain']}")
        lines.append(f"  Amplification: {amp}x{marker}")
        for issue in p["issues"]:
            sev = issue.get("severity", "info").upper()
            msg = f"    [{sev}] {issue['type']}: "
            if issue["type"] == "retry_amplification":
                msg += f"{issue['amplification']}x amplification"
            elif issue["type"] == "timeout_mismatch":
                msg += (f"{issue['parent']} timeout {issue['parent_timeout_ms']}ms "
                        f"< {issue['child']} worst case {issue['child_worst_case_ms']}ms")
            elif issue["type"] == "missing_circuit_breaker":
                msg += f"{issue['source']} -> {issue['target']} ({issue['retries']} retries)"
            lines.append(msg)
    lines.append(f"\nTotal issues: {report['total_issues']}")
    lines.append(f"Critical: {report['critical']}")
    lines.append(f"Max amplification: {report['max_amplification']}x")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="RetryStorm - Microservice retry/timeout topology analyzer")
    parser.add_argument("topology", help="Path to topology YAML file")
    parser.add_argument("-f", "--format",
                        choices=["text", "json", "sarif", "mermaid"],
                        default="text",
                        help="Output format (default: text)")
    parser.add_argument("--max-amp", type=int, default=None,
                        help="Exit with code 1 if max amplification exceeds threshold")
    args = parser.parse_args()

    topo = load_topology(args.topology)

    if args.format == "mermaid":
        print(to_mermaid(topo))
        return

    report = analyze(topo)

    if args.format == "json":
        print(format_json(report))
    elif args.format == "sarif":
        print(to_sarif(report))
    else:
        print(format_text(report))

    if args.max_amp and report["max_amplification"] > args.max_amp:
        sys.exit(1)


if __name__ == "__main__":
    main()
