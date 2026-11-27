# 🛡️ Aegis-RS (`v0.4.0`)

[![Rust CI](https://github.com)](https://github.com)
[![License: Apache-2.0](https://shields.io)](LICENSE)

**Aegis-RS** is a high-performance, zero-telemetry **AI Agent Security Proxy & Guardrail Engine** written in Rust (`Axum` + `Tokio`). It provides a 4-layer enterprise defense pipeline between autonomous AI agents and external tools/LLMs in sub-millisecond latency.

---

## 🏗️ 4-Layer Enterprise Defense Architecture

```text
[ Python / JS AI Agent ]
           │
           ▼  POST /v1/scan
┌─────────────────────────────────────────────────────┐
│                 AEGIS-RS PROXY v0.4.0               │
│  1. RateLimiter   ──► Sliding-Window Flood Control  │
│  2. PolicyEngine  ──► Custom YAML Rules (No-Code)   │
│  3. ThreatScanner ──► Risk Score & RCE/SQLi Block   │
│  4. DataRedactor  ──► OpenAI, AWS, GitHub & PII     │
└─────────────────────────────────────────────────────┘
           │
           ▼  Clean Payload (200) / Blocked (403) / Throttled (429)
[ OpenAI / Anthropic / Local LLM / Shell ]
```

---

## ✨ Key Capabilities (`v0.4.0`)

* **Policy-as-Code (`policies.yaml` & `src/policy.rs`):** Define custom blocked keywords, risk thresholds, and per-agent rate limits in YAML without recompiling Rust code.
* **Sliding-Window Rate Limiter (`src/limiter.rs`):** Enforces per-agent request quotas to stop infinite AI agent loops and DDoS bursts (`HTTP 429`).
* **Real-Time Threat Interception (`src/scanner.rs`):** Blocks Prompt Injections, System Prompt Extraction, Destructive Shell Commands, SQL Injections, and RCE (`HTTP 403`).
* **Automated Secret & PII Vault (`src/redactor.rs`):** Redacts OpenAI keys (`sk-...`), GitHub tokens (`ghp_...`), AWS keys (`AKIA...`), Credit Cards, Emails, and IPv4 addresses.
* **Zero-Dependency Python SDK (`pip install`):** Native Python client for LangChain, CrewAI, and custom agent frameworks.

---

## 📜 Custom Security Policies (`policies.yaml`)
```yaml
rate_limit_per_minute: 60
block_threshold: 70

custom_rules:
  - id: "ORG-001"
    name: "Block Confidential Project Codename"
    pattern: "project-apollo"
    risk_score: 90
```

---

## 🚀 Quick Start

### Option A: Run with Cargo
```bash
cargo run --release
```

### Option B: Run with Docker
```bash
docker build -t aegis-rs:0.4.0 .
docker run -p 8080:8080 aegis-rs:0.4.0
```

---

## 🐍 Python SDK (`pip install`)
```bash
pip install "git+https://github.com"
```

```python
from aegis_client import AegisClient, AegisSecurityBlock

aegis = AegisClient(base_url="http://localhost:8080", agent_id="research-agent")

try:
    res = aegis.scan("Email founder@startup.io with key sk-proj-1234567890abcdefghijklmnop")
    print("Clean Prompt:", res.sanitized_prompt)
except AegisSecurityBlock as e:
    print("Blocked Attack:", e)
```

---

## 🧪 Automated Testing
```bash
cargo test
```

## 📄 License & ⚠️ Disclaimer
Licensed under the [Apache License 2.0](LICENSE).  
*Aegis-RS is provided "as-is" without warranties or guarantees of any kind. Users are responsible for testing and validating security policies in their own environments before production deployment.*

