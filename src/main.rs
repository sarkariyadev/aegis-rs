mod limiter;
mod redactor;
mod scanner;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use limiter::RateLimiter;
use redactor::{DataRedactor, RedactionEvent};
use scanner::{ThreatFinding, ThreatScanner, Verdict};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tracing::{info, warn};

struct AppState {
    scanner: ThreatScanner,
    redactor: DataRedactor,
    limiter: RateLimiter,
    total_scanned: AtomicU64,
    total_blocked: AtomicU64,
    total_rate_limited: AtomicU64,
}

#[derive(Deserialize)]
struct ScanRequest {
    agent_id: Option<String>,
    prompt: String,
}

#[derive(Serialize)]
struct ScanResponse {
    verdict: Verdict,
    risk_score: u8,
    sanitized_prompt: String,
    threats: Vec<ThreatFinding>,
    redactions: Vec<RedactionEvent>,
    rate_limit_remaining: u32,
    latency_us: u128,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    total_scanned: u64,
    total_blocked: u64,
    total_rate_limited: u64,
}

async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        version: "0.3.0",
        total_scanned: state.total_scanned.load(Ordering::Relaxed),
        total_blocked: state.total_blocked.load(Ordering::Relaxed),
        total_rate_limited: state.total_rate_limited.load(Ordering::Relaxed),
    })
}

async fn scan_payload(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> (StatusCode, Json<ScanResponse>) {
    let start = Instant::now();
    let agent = req.agent_id.as_deref().unwrap_or("default-agent");

    // Step 1: Enforce per-agent Rate Limiting (60 requests/min)
    let remaining = match state.limiter.check_rate_limit(agent) {
        Ok(rem) => rem,
        Err(retry_after) => {
            state.total_rate_limited.fetch_add(1, Ordering::Relaxed);
            warn!(agent = agent, retry_after = retry_after, "Rate limit exceeded");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ScanResponse {
                    verdict: Verdict::Block,
                    risk_score: 100,
                    sanitized_prompt: format!("[RATE_LIMITED: RETRY_AFTER_{}S]", retry_after),
                    threats: vec![],
                    redactions: vec![],
                    rate_limit_remaining: 0,
                    latency_us: start.elapsed().as_micros(),
                }),
            );
        }
    };

    state.total_scanned.fetch_add(1, Ordering::Relaxed);

    // Step 2: Threat & Injection Analysis
    let (verdict, risk_score, threats) = state.scanner.analyze(&req.prompt);

    if verdict == Verdict::Block {
        state.total_blocked.fetch_add(1, Ordering::Relaxed);
        warn!(agent = agent, risk_score = risk_score, "Blocked malicious AI agent payload");

        return (
            StatusCode::FORBIDDEN,
            Json(ScanResponse {
                verdict,
                risk_score,
                sanitized_prompt: "[BLOCKED_BY_AEGIS_POLICY]".to_string(),
                threats,
                redactions: vec![],
                rate_limit_remaining: remaining,
                latency_us: start.elapsed().as_micros(),
            }),
        );
    }

    // Step 3: PII & Secret Vault Redaction
    let (sanitized_prompt, redactions) = state.redactor.sanitize(&req.prompt);

    (
        StatusCode::OK,
        Json(ScanResponse {
            verdict,
            risk_score,
            sanitized_prompt,
            threats,
            redactions,
            rate_limit_remaining: remaining,
            latency_us: start.elapsed().as_micros(),
        }),
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let shared_state = Arc::new(AppState {
        scanner: ThreatScanner::new(),
        redactor: DataRedactor::new(),
        limiter: RateLimiter::new(60),
        total_scanned: AtomicU64::new(0),
        total_blocked: AtomicU64::new(0),
        total_rate_limited: AtomicU64::new(0),
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/v1/scan", post(scan_payload))
        .with_state(shared_state);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    info!("🛡️ Aegis-RS v0.3.0 Security Proxy listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}




 

 

          

       
    

    
   
