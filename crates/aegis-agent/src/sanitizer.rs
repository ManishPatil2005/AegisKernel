//! # Command-Line Argument & Telemetry Sanitizer
//!
//! Provides high-throughput regex masking of credentials, bearer tokens,
//! and private keys before telemetry leaves the host boundary.

use regex::Regex;
use std::sync::LazyLock;

static PASSWORD_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(password|passwd|pwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*['"]?([^\s'"]+)"#)
        .expect("valid regex")
});

static AWS_KEY_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"AKIA[0-9A-Z]{16}"#).expect("valid regex")
});

/// Sanitizes an input string by redacting detected credentials and sensitive tokens.
pub fn sanitize_telemetry_string(input: &str) -> String {
    let intermediate = PASSWORD_PATTERN.replace_all(input, "$1=[REDACTED]");
    AWS_KEY_PATTERN.replace_all(&intermediate, "AKIA[REDACTED_AWS_KEY]").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_redaction() {
        let cmd = "curl -u admin:secretpassword123 https://api.enterprise.com";
        let sanitized = sanitize_telemetry_string(cmd);
        assert!(!sanitized.contains("secretpassword123"));
        assert!(sanitized.contains("[REDACTED]"));
    }

    #[test]
    fn test_aws_key_redaction() {
        let cmd = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let sanitized = sanitize_telemetry_string(cmd);
        assert!(!sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(sanitized.contains("AKIA[REDACTED_AWS_KEY]"));
    }
}
