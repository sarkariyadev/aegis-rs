# Aegis-RS (v0.4.0)

A lightweight, local-first security proxy for AI agents written in Rust (`Axum` + `Tokio`). It sits between your AI agent and external tools/LLMs to filter prompt injections, block dangerous commands, and redact sensitive API keys.

*Note: This is an early-stage learning project under active development.*

## Architecture

```text

[ Python / JS AI Agent ]
          |
          v  POST /v1/scan
+-------------------------------------------------------+

|                  AEGIS-RS PROXY v0.4.0                |
|  1. RateLimiter   -> Per-agent request rate control   |
|  2. PolicyEngine  -> Custom YAML rules (policies.yaml)|
|  3. ThreatScanner -> Regex & risk score filtering     |
|  4. DataRedactor  -> Masks API keys, emails & IPs     |
+-------------------------------------------------------+
          |
          v  Clean Payload (200) / Blocked (403) / Rate Limited (429)
[ OpenAI / Anthropic / Local LLM / Shell ]
```

## Features (v0.4.0)

* **YAML Policy Config (`policies.yaml` & `src/policy.rs`):** Add custom blocked keywords and adjust rate limits without recompiling Rust code.
* **Rate Limiter (`src/limiter.rs`):** Basic sliding-window request limit per agent (`HTTP 429`).
* **Threat Scanner (`src/scanner.rs`):** Scans prompts for common prompt injections, destructive shell commands, and SQL patterns (`HTTP 403`).
* **PII & Secret Redactor (`src/redactor.rs`):** Masks OpenAI keys (`sk-...`), GitHub tokens (`ghp_...`), AWS keys (`AKIA...`), credit cards, and emails.
* **Python Client (`python/aegis_client.py`):** Simple Python wrapper to connect your agent to the proxy.

## Custom Policies (`policies.yaml`)

```yaml
rate_limit_per_minute: 60
block_threshold: 70

custom_rules:
  - id: "ORG-001"
    name: "Block Confidential Project Codename"
    pattern: "project-apollo"
    risk_score: 90
```

## Quick Start

### Option A: Run with Cargo
```bash
cargo run --release
```

### Option B: Run with Docker
```bash
docker build -t aegis-rs:0.4.0 .
docker run -p 8080:8080 aegis-rs:0.4.0
```

## Python Client Usage

Install from the `master` branch:
```bash
pip install "git+https://github.com"
```

Example usage:
```python
from aegis_client import AegisClient, AegisSecurityBlock

aegis = AegisClient(base_url="http://localhost:8080")

try:
    res = aegis.scan("Email founder@startup.com")
    print("Clean Prompt:", res.sanitized_prompt)
except AegisSecurityBlock as e:
    print("Blocked Attack:", e)
```

## Testing

```bash
cargo test
```

## License

Apache-2.0
