use regex::{Captures, Regex};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RedactionEvent {
    pub category: String,
    pub placeholder: String,
}

pub struct DataRedactor {
    rules: Vec<(Regex, &'static str, &'static str)>,
}

impl DataRedactor {
    pub fn new() -> Self {
        let rules = vec![
            (
                Regex::new(r"sk-(?:proj-)?[a-zA-Z0-9_-]{20,}").unwrap(),
                "OPENAI_API_KEY",
                "[REDACTED_OPENAI_KEY]",
            ),
            (
                Regex::new(r"gh[pousr]_[a-zA-Z0-9]{36,}").unwrap(),
                "GITHUB_TOKEN",
                "[REDACTED_GITHUB_TOKEN]",
            ),
            (
                Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                "AWS_ACCESS_KEY",
                "[REDACTED_AWS_KEY]",
            ),
            (
                Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap(),
                "CREDIT_CARD",
                "[REDACTED_CREDIT_CARD]",
            ),
            (
                Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
                "EMAIL_ADDRESS",
                "[REDACTED_EMAIL]",
            ),
            (
                Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
                "IPV4_ADDRESS",
                "[REDACTED_IP]",
            ),
        ];

        Self { rules }
    }

    pub fn sanitize(&self, input: &str) -> (String, Vec<RedactionEvent>) {
        let mut current = input.to_string();
        let mut events = Vec::new();

        for (pattern, category, placeholder) in &self.rules {
            let replaced = pattern.replace_all(&current, |_caps: &Captures| {
                events.push(RedactionEvent {
                    category: category.to_string(),
                    placeholder: placeholder.to_string(),
                });
                *placeholder
            });
            current = replaced.to_string();
        }

        (current, events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_secret_redaction() {
        let redactor = DataRedactor::new();
        let payload = "Connect to 192.168.1.50 as dev@aegis.io with sk-proj-1234567890abcdefghijklmnop";
        let (clean, events) = redactor.sanitize(payload);

        assert_eq!(events.len(), 3);
        assert_eq!(
            clean,
            "Connect to [REDACTED_IP] as [REDACTED_EMAIL] with [REDACTED_OPENAI_KEY]"
        );
    }
}
