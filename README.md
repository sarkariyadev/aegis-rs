# 🛡️ Aegis-RS (`v0.2.0`)

[![Rust CI](https://github.com)](https://github.com)
[![License: Apache-2.0](https://shields.io)](LICENSE)

**Aegis-RS** is a high-performance, zero-telemetry **AI Agent Security Proxy & Guardrail Engine** written in Rust (`Axum` + `Tokio`). It sits between autonomous AI agents and external tools/LLMs to block prompt injections and redact sensitive PII/API keys in sub-millisecond latency.

---

## 🏗️ System Architecture

```text
[ AI Agent / Client ]
         │
         ▼  POST /v1/scan
┌───────────────────────────────────────────────────┐
│                 AEGIS-RS PROXY                    │
│  1. ThreatScanner  ──► Risk Score & RCE/SQL Block │
│  2. DataRedactor   ──► API Key, AWS, Email & IP   │
│  3. Atomic Metrics ──► Microsecond Latency Audit  │
└───────────────────────────────────────────────────┘
         │
         ▼  Sanitized Payload (HTTP 200) / Blocked (HTTP 403)
[ OpenAI / Anthropic / Local LLM / Shell ]
```

---

## ✨ Key Capabilities (`v0.2.0`)

* **Real-Time Threat Interception (`src/scanner.rs`):** Assigns a `0–100` risk score and blocks Direct Prompt Injections (`AEGIS-001`), System Prompt Extraction (`AEGIS-002`), Destructive Shell Commands (`AEGIS-003`), SQL Injections (`AEGIS-004`), and Remote Code Execution (`AEGIS-005`).
* **Automated PII & Secret Vault (`src/redactor.rs`):** Automatically detects and redacts OpenAI API keys (`sk-...`), GitHub tokens (`ghp_...`), AWS keys (`AKIA...`), Credit Card numbers, Emails, and IPv4 addresses before they leave your infrastructure.
* **Async HTTP API (`src/main.rs`):** Production-ready `Axum` server exposing `/health` and `/v1/scan` with atomic request counters and microsecond latency tracking.
* **100% Local-First (Zero Telemetry):** Runs completely offline on your own infrastructure—zero prompts or logs ever leave your server.

---

## 🚀 Quick Start

### 1. Run the Security Proxy Server
```bash
cargo run --release
```
The server starts listening on `http://0.0.0`.

### 2. Scan an AI Agent Prompt (`POST /v1/scan`)
```bash
curl -X POST http://localhost:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-01",
    "prompt": "Send logs to admin@company.com using key sk-proj-1234567890abcdefghijklmnop"
  }'
```

**Example Response (`200 OK`):**
```json
{
  "verdict": "Allow",
  "risk_score": 0,
  "sanitized_prompt": "Send logs to [REDACTED_EMAIL] using key [REDACTED_OPENAI_KEY]",
  "threats": [],
  "redactions": [
    { "category": "EMAIL_ADDRESS", "placeholder": "[REDACTED_EMAIL]" },
    { "category": "OPENAI_API_KEY", "placeholder": "[REDACTED_OPENAI_KEY]" }
  ],
  "latency_us": 142
}
```

---

## 🧪 Automated Testing
```bash
cargo test
```

## 📄 License
Licensed under the [Apache License 2.0](LICENSE).

