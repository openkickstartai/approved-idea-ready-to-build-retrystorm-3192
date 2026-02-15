# 🌩️ RetryStorm

**Microservice retry/timeout topology analyzer** — Catch every retry storm call chain before cascading failures crush production.

RetryStorm statically analyzes your service topology configs to find:
- **Retry amplification** — A×B×C retries multiply exponentially
- **Timeout mismatches** — Parent timeouts too short for child retries
- **Missing circuit breakers** — High-retry edges without protection

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# Analyze a topology
python main.py example_topology.yaml

# JSON output for programmatic use
python main.py example_topology.yaml -f json

# Mermaid diagram for visualization
python main.py example_topology.yaml -f mermaid

# CI gate: fail if amplification > 16x
python main.py example_topology.yaml --max-amp 16

# SARIF for GitHub Code Scanning
python main.py example_topology.yaml -f sarif > results.sarif
```

## 📐 Topology YAML Format

```yaml
services:
  - name: api-gateway
    calls:
      - target: order-service
        retries: 3
        timeout_ms: 5000
        circuit_breaker: false
  - name: order-service
    calls:
      - target: payment-service
        retries: 3
        timeout_ms: 3000
        circuit_breaker: false
```

## 📊 Why Pay for RetryStorm?

A single retry storm incident costs **$10K-$500K** in downtime, SLA penalties, and engineering time. RetryStorm catches these *before* they hit production, in your CI pipeline, for a fraction of the cost.

**Real-world example:** 3 services each with 3 retries = **64x amplification**. One slow database turns into 64x the traffic, cascading into a full outage.

## 💰 Pricing

| Feature | Free | Pro ($29/mo) | Enterprise ($199/mo) |
|---|---|---|---|
| Retry amplification detection | ✅ | ✅ | ✅ |
| Timeout mismatch detection | ✅ | ✅ | ✅ |
| Circuit breaker warnings | ✅ | ✅ | ✅ |
| Text + JSON output | ✅ | ✅ | ✅ |
| Max services | 10 | 100 | Unlimited |
| SARIF output (GitHub integration) | ❌ | ✅ | ✅ |
| Mermaid diagram generation | ❌ | ✅ | ✅ |
| CI gate mode (--max-amp) | ❌ | ✅ | ✅ |
| Istio/Envoy config auto-import | ❌ | ❌ | ✅ |
| Helm chart scanning | ❌ | ❌ | ✅ |
| Slack/PagerDuty alerts | ❌ | ❌ | ✅ |
| Priority support + SLA | ❌ | ❌ | ✅ |

## 🏗️ CI/CD Integration

```yaml
# .github/workflows/retrystorm.yml
- name: RetryStorm Check
  run: python main.py topology.yaml --max-amp 16
```

Fails the build if any call chain has retry amplification > 16x.

## License

MIT (Free tier) | Commercial license required for Pro/Enterprise features.
