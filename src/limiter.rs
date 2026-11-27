use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct AgentWindow {
    count: u32,
    window_start: Instant,
}

pub struct RateLimiter {
    max_requests: u32,
    window_duration: Duration,
    agents: Mutex<HashMap<String, AgentWindow>>,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            max_requests: max_requests_per_minute,
            window_duration: Duration::from_secs(60),
            agents: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_rate_limit(&self, agent_id: &str) -> Result<u32, u64> {
        let mut map = self.agents.lock().unwrap();
        let now = Instant::now();

        let entry = map.entry(agent_id.to_string()).or_insert(AgentWindow {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) >= self.window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= self.max_requests {
            let retry_after = self
                .window_duration
                .saturating_sub(now.duration_since(entry.window_start))
                .as_secs()
                .max(1);
            return Err(retry_after);
        }

        entry.count += 1;
        Ok(self.max_requests - entry.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_blocks_flood() {
        let limiter = RateLimiter::new(2);
        assert_eq!(limiter.check_rate_limit("agent-alpha"), Ok(1));
        assert_eq!(limiter.check_rate_limit("agent-alpha"), Ok(0));
        assert!(limiter.check_rate_limit("agent-alpha").is_err());
    }
}
