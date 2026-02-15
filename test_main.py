"""Tests for RetryStorm analyzer."""
import json
import pytest
from main import build_graph, find_paths, analyze_path, analyze, entry_points, to_mermaid, to_sarif

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
    assert report["high"] == 0
    assert len(report["paths"]) == 1
    assert report["paths"][0]["amplification"] == 2


def test_timeout_mismatch_detected():
    """frontend timeout 1000ms but backend->db needs 500*4=2000ms."""
    report = analyze(TIMEOUT_TOPO)
    tm = [i for i in report["issues"] if i["type"] == "timeout_mismatch"]
    assert len(tm) >= 1
    assert tm[0]["parent_timeout"] == 1000
    assert tm[0]["needed"] == 2000


def test_missing_circuit_breaker():
    """Edges with retries>=3 and no circuit breaker should warn."""
    report = analyze(DANGEROUS_TOPO)
    cb = [i for i in report["issues"] if i["type"] == "no_circuit_breaker"]
    assert len(cb) == 3  # all 3 edges have retries=3, no CB


def test_entry_points_detected():
    """Gateway is the only entry point (not a target of any call)."""
    graph = build_graph(DANGEROUS_TOPO)
    entries = entry_points(graph)
    assert entries == ["gateway"]


def test_mermaid_output():
    """Mermaid diagram contains graph structure."""
    mmd = to_mermaid(DANGEROUS_TOPO)
    assert "graph LR" in mmd
    assert "gateway" in mmd
    assert "retries=3" in mmd
    assert mmd.count("-->") == 3


def test_sarif_output_valid():
    """SARIF output is valid JSON with correct structure."""
    report = analyze(DANGEROUS_TOPO)
    sarif_str = to_sarif(report)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "RetryStorm"
    assert len(sarif["runs"][0]["results"]) > 0


def test_find_paths_no_cycles():
    """Cyclic graphs should not cause infinite recursion."""
    cyclic = {
        "services": [
            {"name": "a", "calls": [{"target": "b", "retries": 2, "timeout_ms": 1000}]},
            {"name": "b", "calls": [{"target": "a", "retries": 2, "timeout_ms": 1000}]}
        ]
    }
    report = analyze(cyclic)
    assert report is not None
    assert len(report["paths"]) >= 1
