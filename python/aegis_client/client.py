import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import List, Dict, Any


class AegisSecurityBlock(Exception):
    """Raised when Aegis-RS blocks a prompt due to high security risk."""
    def __init__(self, risk_score: int, threats: List[Dict[str, Any]]):
        self.risk_score = risk_score
        self.threats = threats
        super().__init__(f"Payload blocked by Aegis-RS (Risk Score: {risk_score}/100)")


@dataclass
class ScanResult:
    verdict: str
    risk_score: int
    sanitized_prompt: str
    threats: List[Dict[str, Any]]
    redactions: List[Dict[str, Any]]
    rate_limit_remaining: int
    latency_us: int


class AegisClient:
    """Zero-dependency Python SDK for the Aegis-RS Security Proxy (v0.3.0)."""

    def __init__(self, base_url: str = "http://localhost:8080", agent_id: str = "python-agent"):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id

    def scan(self, prompt: str, raise_on_block: bool = True) -> ScanResult:
        url = f"{self.base_url}/v1/scan"
        payload = json.dumps({
            "agent_id": self.agent_id,
            "prompt": prompt
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                data = json.loads(e.read().decode("utf-8"))
                if raise_on_block:
                    raise AegisSecurityBlock(data["risk_score"], data["threats"])
            else:
                raise

        return ScanResult(
            verdict=data["verdict"],
            risk_score=data["risk_score"],
            sanitized_prompt=data["sanitized_prompt"],
            threats=data["threats"],
            redactions=data["redactions"],
            rate_limit_remaining=data.get("rate_limit_remaining", 0),
            latency_us=data["latency_us"],
        )
