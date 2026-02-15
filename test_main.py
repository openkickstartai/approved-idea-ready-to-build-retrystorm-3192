"""Tests for RetryStorm analyzer."""
import json
import pytest
from main import (build_graph, find_paths, analyze_path, analyze,
                  entry_points, to_mermaid, to_sarif, format_json, format_text)

DANGEROUS_TOPO = {
    "services": [
        {"name": "gateway", "calls": [
            {"target": "orders", "retries": 3, "timeout_ms": 5000, "circuit_breaker": False}]},
        {"name": "orders", "calls": [
            {"target": "payments", "retries": 3, "timeout_ms": 3000, "circuit_breaker": False}]},
        {"name": "payments", "calls": [
            {"target": "fraud", "retries": 3, "timeout_ms": 2000, "circuit_breaker": False}]},
        {"name": "fraud", "calls": []}
    ]
}

SAFE_TOPO = {
    "services": [
        {"name": "api", "calls": [
            {"target": "cache", "retries": 1, "timeout_ms": 1000, "circuit_breaker": True}]},
        {"name": "cache", "calls": []}
    ]
}

TIMEOUT_TOPO = {
    "services": [
        {"name": "frontend", "calls": [
            {"target": "backend", "retries": 0, "timeout_ms": 1000, "circuit_breaker": True}]},
        {"name": "backend", "calls": [
            {"target": "db", "retries": 3, "timeout_ms": 500, "circuit_breaker": False}]},
        {"name": "db", "calls": []}
    ]
}


# ──────────────────────────────────────────────
# Core analysis tests
# ──────────────────────────────────────────────

def test_retry_amplification_critical():
    """3 hops x 3 retries each = (3+1)^3 = 64x amplification -> critical."""
    report = analyze(DANGEROUS_TOPO)
    assert report["critical"] >= 1
    storms = [p for p in report["paths"] if p["amplification"] == 64]
    assert len(storms) == 1
    assert "gateway" in storms[0]["chain"]
    assert "fraud" in storms[0]["chain"]


def test_safe_topology_no_issues():
    """A simple 2-service chain with 1 retry and circuit breaker is safe."""
    report = analyze(SAFE_TOPO)
    assert report["total_issues"] == 0
    assert report["critical"] == 0


def test_timeout_mismatch():
    """Parent timeout < child retries * child timeout -> timeout mismatch."""
    report = analyze(TIMEOUT_TOPO)
    timeout_issues = [
        issue for p in report["paths"] for issue in p["issues"]
        if issue["type"] == "timeout_mismatch"
    ]
    assert len(timeout_issues) >= 1


def test_entry_points():
    graph = build_graph(DANGEROUS_TOPO)
    eps = entry_points(graph)
    assert eps == ["gateway"]


def test_find_paths():
    graph = build_graph(SAFE_TOPO)
    paths = find_paths(graph, "api")
    assert len(paths) == 1
    assert paths[0][0][0] == "api"
    assert paths[0][1][0] == "cache"


def test_missing_circuit_breaker():
    report = analyze(DANGEROUS_TOPO)
    cb_issues = [
        issue for p in report["paths"] for issue in p["issues"]
        if issue["type"] == "missing_circuit_breaker"
    ]
    assert len(cb_issues) >= 1


def test_mermaid_output():
    output = to_mermaid(SAFE_TOPO)
    assert "graph LR" in output
    assert "api" in output
    assert "cache" in output


def test_analyze_path_no_edges():
    """Single-node path has amplification 1 and no issues."""
    result = analyze_path([("lonely", None)])
    assert result["amplification"] == 1
    assert result["issues"] == []


def test_text_output():
    """Text format contains expected report elements."""
    report = analyze(DANGEROUS_TOPO)
    text = format_text(report)
    assert "RetryStorm Analysis Report" in text
    assert "64x" in text
    assert "Critical:" in text


# ──────────────────────────────────────────────
# JSON output format tests
# ──────────────────────────────────────────────

def test_json_output_is_valid_json():
    """format_json returns a parseable JSON string."""
    report = analyze(DANGEROUS_TOPO)
    output = format_json(report)
    parsed = json.loads(output)  # raises if invalid
    assert isinstance(parsed, dict)


def test_json_output_has_chains_and_summary():
    """JSON output contains top-level chains[] and summary{} keys."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(format_json(report))
    assert "chains" in parsed
    assert "summary" in parsed
    assert isinstance(parsed["chains"], list)
    assert isinstance(parsed["summary"], dict)


def test_json_summary_fields():
    """summary has total_chains, max_multiplier, critical_count."""
    report = analyze(DANGEROUS_TOPO)
    summary = json.loads(format_json(report))["summary"]
    assert "total_chains" in summary
    assert "max_multiplier" in summary
    assert "critical_count" in summary
    assert isinstance(summary["total_chains"], int)
    assert isinstance(summary["max_multiplier"], int)
    assert isinstance(summary["critical_count"], int)


def test_json_chain_structure():
    """Each chain entry has chain, amplification, issues."""
    report = analyze(DANGEROUS_TOPO)
    chains = json.loads(format_json(report))["chains"]
    assert len(chains) >= 1
    for chain in chains:
        assert "chain" in chain
        assert "amplification" in chain
        assert "issues" in chain
        assert isinstance(chain["chain"], str)
        assert isinstance(chain["amplification"], int)
        assert isinstance(chain["issues"], list)


def test_json_dangerous_values():
    """Dangerous topology: 64x amp, critical >= 1."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(format_json(report))
    assert parsed["summary"]["max_multiplier"] == 64
    assert parsed["summary"]["critical_count"] >= 1
    assert parsed["summary"]["total_chains"] >= 1


def test_json_safe_values():
    """Safe topology: low amp, zero critical."""
    report = analyze(SAFE_TOPO)
    parsed = json.loads(format_json(report))
    assert parsed["summary"]["critical_count"] == 0
    assert parsed["summary"]["max_multiplier"] <= 4


def test_json_issues_populated():
    """Dangerous topo chains contain issues with type and severity."""
    report = analyze(DANGEROUS_TOPO)
    chains = json.loads(format_json(report))["chains"]
    all_issues = [i for c in chains for i in c["issues"]]
    assert len(all_issues) > 0
    for issue in all_issues:
        assert "type" in issue
        assert "severity" in issue


# ──────────────────────────────────────────────
# SARIF output format tests
# ──────────────────────────────────────────────

def test_sarif_is_valid_json():
    """to_sarif returns parseable JSON."""
    report = analyze(DANGEROUS_TOPO)
    output = to_sarif(report)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_sarif_version():
    """SARIF output declares version 2.1.0."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    assert parsed["version"] == "2.1.0"


def test_sarif_schema_field():
    """SARIF output includes $schema pointing to OASIS spec."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    assert "$schema" in parsed
    assert "sarif-schema-2.1.0" in parsed["$schema"]


def test_sarif_runs_structure():
    """SARIF has exactly one run with tool and results."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    assert "runs" in parsed
    assert len(parsed["runs"]) == 1
    run = parsed["runs"][0]
    assert "tool" in run
    assert "results" in run


def test_sarif_tool_driver():
    """SARIF tool.driver has name, version, and rules."""
    report = analyze(DANGEROUS_TOPO)
    driver = json.loads(to_sarif(report))["runs"][0]["tool"]["driver"]
    assert driver["name"] == "RetryStorm"
    assert "version" in driver
    assert "rules" in driver
    assert isinstance(driver["rules"], list)
    assert len(driver["rules"]) >= 1


def test_sarif_rule_id_retrystorm_001():
    """Retry amplification issues use rule id retrystorm-001."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    results = parsed["runs"][0]["results"]
    amp_results = [r for r in results if r["ruleId"] == "retrystorm-001"]
    assert len(amp_results) >= 1


def test_sarif_rule_ids_for_all_issue_types():
    """Each issue type maps to a distinct rule id."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    # dangerous topo should trigger at least retry_amplification and missing_circuit_breaker
    assert "retrystorm-001" in rule_ids
    assert "retrystorm-003" in rule_ids


def test_sarif_severity_mapping_critical_to_error():
    """Critical severity maps to SARIF level 'error'."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    results = parsed["runs"][0]["results"]
    amp_results = [r for r in results if r["ruleId"] == "retrystorm-001"]
    # 64x amp is critical -> error
    assert any(r["level"] == "error" for r in amp_results)


def test_sarif_severity_mapping_warning():
    """Warning severity maps to SARIF level 'warning'."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    results = parsed["runs"][0]["results"]
    cb_results = [r for r in results if r["ruleId"] == "retrystorm-003"]
    assert any(r["level"] == "warning" for r in cb_results)


def test_sarif_results_have_locations():
    """Every SARIF result has a locations array with physicalLocation."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    results = parsed["runs"][0]["results"]
    assert len(results) > 0
    for r in results:
        assert "locations" in r
        assert len(r["locations"]) >= 1
        loc = r["locations"][0]
        assert "physicalLocation" in loc
        assert "artifactLocation" in loc["physicalLocation"]
        assert "uri" in loc["physicalLocation"]["artifactLocation"]


def test_sarif_results_have_messages():
    """Every SARIF result has a message with text."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    results = parsed["runs"][0]["results"]
    for r in results:
        assert "message" in r
        assert "text" in r["message"]
        assert len(r["message"]["text"]) > 0


def test_sarif_safe_topology_empty_results():
    """Safe topology produces SARIF with zero results."""
    report = analyze(SAFE_TOPO)
    parsed = json.loads(to_sarif(report))
    assert len(parsed["runs"][0]["results"]) == 0


def test_sarif_timeout_topo_has_results():
    """Timeout topology produces SARIF results for timeout mismatch."""
    report = analyze(TIMEOUT_TOPO)
    parsed = json.loads(to_sarif(report))
    results = parsed["runs"][0]["results"]
    timeout_results = [r for r in results if r["ruleId"] == "retrystorm-002"]
    assert len(timeout_results) >= 1


def test_sarif_rules_sorted_by_id():
    """SARIF rules are sorted by id for deterministic output."""
    report = analyze(DANGEROUS_TOPO)
    parsed = json.loads(to_sarif(report))
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert rule_ids == sorted(rule_ids)
