# 🛡️ Aegis-RS

**High-Performance AI Agent Security Guardrails & Prompt Injection Shield built in Rust.**

`aegis-rs` is a lightweight, blazing-fast security layer designed to protect autonomous AI Agents from prompt injections, unauthorized system commands, and sensitive data leaks (API keys, credentials) in real time.

## 🚀 Key Features
- **Prompt Injection Detection:** Blocks malicious instructions (`ignore previous instructions`, `system override`, etc.) before they reach the LLM.
- **Command & Database Protection:** Prevents dangerous shell (`rm -rf`) and SQL (`DROP TABLE`) execution by AI agents.
- **Secret Leak Prevention:** Scans inputs and outputs to prevent accidental exposure of API keys and passwords.
- **Zero-Overhead Rust Engine:** Built in memory-safe Rust for sub-millisecond latency.

## 📦 Quick Start (Docker)
```bash
docker build -t aegis-rs .
docker run --rm aegis-rs
```

## ⚠️ Disclaimer
> **Beta Software:** `aegis-rs` (`v0.1.0`) is currently in active early-stage development (Beta). Please audit and test thoroughly before deploying in production environments.

## 📄 License
Licensed under the **Apache License 2.0**. See `LICENSE` for details.
