mod limiter;
mod policy;
mod redactor;
mod scanner;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use limiter::RateLimiter;
use policy::PolicyConfig;
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
    policy: PolicyConfig,
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
    custom_rules_loaded: usize,
    total_scanned: u64,
    total_blocked: u64,
    total_rate_limited: u64,
}

async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        version: "0.4.0",
        custom_rules_loaded: state.policy.custom_rules.len(),
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

    // Step 1: Per-agent Rate Limiting from policies.yaml
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

    // Step 2: Built-in Threat Scanner + Custom YAML Policy Rules
    let (_, base_risk, mut threats) = state.scanner.analyze(&req.prompt);
    let (custom_risk, custom_threats) = state.policy.evaluate_custom_rules(&req.prompt);
    threats.extend(custom_threats);

    let total_risk = base_risk.max(custom_risk);
    let verdict = if total_risk >= state.policy.block_threshold {
        Verdict::Block
    } else if total_risk > 0 {
        Verdict::RedactAndAllow
    } else {
        Verdict::Allow
    };

    if verdict == Verdict::Block {
        state.total_blocked.fetch_add(1, Ordering::Relaxed);
        warn!(agent = agent, risk_score = total_risk, "Blocked malicious AI agent payload");

        return (
            StatusCode::FORBIDDEN,
            Json(ScanResponse {
                verdict,
                risk_score: total_risk,
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
            risk_score: total_risk,
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

    let policy = PolicyConfig::load_from_file("policies.yaml");
    let rate_limit = policy.rate_limit_per_minute;
    let rules_count = policy.custom_rules.len();

    let shared_state = Arc::new(AppState {
        scanner: ThreatScanner::new(),
        redactor: DataRedactor::new(),
        limiter: RateLimiter::new(rate_limit),
        policy,
        total_scanned: AtomicU64::new(0),
        total_blocked: AtomicU64::new(0),
        total_rate_limited: AtomicU64::new(0),
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/v1/scan", post(scan_payload))
        .with_state(shared_state);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    info!(
        "🛡️ Aegis-RS v0.4.0 listening on http://{} ({} custom YAML rules loaded)",
        addr, rules_count
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

                    
           
          
        

 
              
     

      




 

 

          

       
    

    
   
