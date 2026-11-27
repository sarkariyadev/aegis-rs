use crate::scanner::ThreatFinding;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub risk_score: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    pub rate_limit_per_minute: u32,
    pub block_threshold: u8,
    pub custom_rules: Vec<CustomRule>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: 60,
            block_threshold: 70,
            custom_rules: vec![],
        }
    }
}

impl PolicyConfig {
    pub fn load_from_file(path: &str) -> Self {
        match fs::read_to_string(path) {
            Ok(content) => serde_yaml::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn evaluate_custom_rules(&self, input: &str) -> (u8, Vec<ThreatFinding>) {
        let lower = input.to_lowercase();
        let mut max_risk = 0u8;
        let mut findings = Vec::new();

        for rule in &self.custom_rules {
            if lower.contains(&rule.pattern.to_lowercase()) {
                max_risk = max_risk.max(rule.risk_score);
                findings.push(ThreatFinding {
                    rule_id: rule.id.clone(),
                    category: format!("Custom Policy: {}", rule.name),
                    severity: "CRITICAL".to_string(),
                    matched_pattern: rule.pattern.clone(),
                });
            }
        }

        (max_risk, findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_yaml_policy_rule() {
        let yaml = r#"
rate_limit_per_minute: 30
block_threshold: 70
custom_rules:
  - id: "ORG-999"
    name: "Secret Codename"
    pattern: "omega-vault"
    risk_score: 85
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let (risk, findings) = cfg.evaluate_custom_rules("Access omega-vault immediately");
        assert_eq!(risk, 85);
        assert_eq!(findings.len(), 1);
    }
}
