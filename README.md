# 🛡️ Aegis-RS (`v0.3.0`)

[![Rust CI](https://github.com)](https://github.com)
[![License: Apache-2.0](https://shields.io)](LICENSE)

**Aegis-RS** is a high-performance, zero-telemetry **AI Agent Security Proxy & Guardrail Engine** written in Rust (`Axum` + `Tokio`). It provides a 3-layer defense pipeline between autonomous AI agents and external tools/LLMs in sub-millisecond latency.

---

## 🏗️ 3-Layer Defense Architecture

```text
[ Python / JS AI Agent ]
           │
           ▼  POST /v1/scan
┌─────────────────────────────────────────────────────┐
│                 AEGIS-RS PROXY v0.3.0               │
│  1. RateLimiter   ──► Sliding-Window Flood Control  │
│  2. ThreatScanner ──► Risk Score & RCE/SQLi Block   │
│  3. DataRedactor  ──► OpenAI, AWS, GitHub & PII     │
└─────────────────────────────────────────────────────┘
           │
           ▼  Clean Payload (200) / Blocked (403) / Throttled (429)
[ OpenAI / Anthropic / Local LLM / Shell ]
```

---

## ✨ Key Capabilities (`v0.3.0`)

* **Sliding-Window Rate Limiter (`src/limiter.rs`):** Enforces per-agent request quotas (default `60 req/min`) to stop infinite AI agent loops and DDoS bursts (`HTTP 429`).
* **Real-Time Threat Interception (`src/scanner.rs`):** Assigns a `0–100` risk score and blocks Prompt Injections, System Prompt Extraction, Destructive Shell Commands, SQL Injections, and RCE (`HTTP 403`).
* **Automated Secret & PII Vault (`src/redactor.rs`):** Redacts OpenAI keys (`sk-...`), GitHub tokens (`ghp_...`), AWS keys (`AKIA...`), Credit Cards, Emails, and IPv4 addresses before they leave your network.
* **Zero-Dependency Python SDK (`python/aegis_client.py`):** Native Python client for LangChain, CrewAI, and custom agent frameworks.
* **Production Docker Image (`Dockerfile`):** Multi-stage Debian slim build for instant deployment.

---

## 🚀 Quick Start

### Option A: Run with Cargo
```bash
cargo run --release
```

### Option B: Run with Docker
```bash
docker build -t aegis-rs:0.3.0 .
docker run -p 8080:8080 aegis-rs:0.3.0
```

### Scan a Payload (`POST /v1/scan`)
```bash
curl -X POST http://localhost:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-01",
    "prompt": "Send logs to admin@company.com using key sk-proj-1234567890abcdefghijklmnop"
  }'
```

---
## 🐍 Python SDK (`pip install`)
Install the zero-dependency Python client directly via `pip`:
```bash
pip install "git+https://github.com"
```

Use it in your LangChain, CrewAI, or custom Python AI agents:
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
