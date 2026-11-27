mod redactor;
mod scanner;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
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
    total_scanned: AtomicU64,
    total_blocked: AtomicU64,
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
    latency_us: u128,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    total_scanned: u64,
    total_blocked: u64,
}

async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        version: env!("CARGO_PKG_VERSION"),
        total_scanned: state.total_scanned.load(Ordering::Relaxed),
        total_blocked: state.total_blocked.load(Ordering::Relaxed),
    })
}

async fn scan_payload(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> (StatusCode, Json<ScanResponse>) {
    let start = Instant::now();
    state.total_scanned.fetch_add(1, Ordering::Relaxed);

    let (verdict, risk_score, threats) = state.scanner.analyze(&req.prompt);

    if verdict == Verdict::Block {
        state.total_blocked.fetch_add(1, Ordering::Relaxed);
        warn!(
            agent = req.agent_id.as_deref().unwrap_or("unknown"),
            risk_score = risk_score,
            "Blocked malicious AI agent payload"
        );

        let response = ScanResponse {
            verdict,
            risk_score,
            sanitized_prompt: "[BLOCKED_BY_AEGIS_POLICY]".to_string(),
            threats,
            redactions: vec![],
            latency_us: start.elapsed().as_micros(),
        };
        return (StatusCode::FORBIDDEN, Json(response));
    }

    let (sanitized_prompt, redactions) = state.redactor.sanitize(&req.prompt);

    let response = ScanResponse {
        verdict,
        risk_score,
        sanitized_prompt,
        threats,
        redactions,
        latency_us: start.elapsed().as_micros(),
    };

    (StatusCode::OK, Json(response))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let shared_state = Arc::new(AppState {
        scanner: ThreatScanner::new(),
        redactor: DataRedactor::new(),
        total_scanned: AtomicU64::new(0),
        total_blocked: AtomicU64::new(0),
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/v1/scan", post(scan_payload))
        .with_state(shared_state);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    info!(
        "🛡️ Aegis-RS v{} Security Proxy listening on http://{}",
        env!("CARGO_PKG_VERSION"),
        addr
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

       
    

    
   
