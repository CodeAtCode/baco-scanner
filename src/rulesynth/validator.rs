//! Semgrep rule validation using `semgrep --validate` subprocess

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

/// Error type for rule validation failures
#[derive(Debug, Clone)]
pub enum RuleError {
    /// LLM API error
    LlmError(String),
    /// YAML parsing error
    YamlError(String),
    /// Semgrep validation error
    SemgrepError(String),
    /// Semgrep binary not found
    SemgrepNotFound,
    /// I/O error
    IoError(String),
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::LlmError(msg) => write!(f, "LLM error: {}", msg),
            RuleError::YamlError(msg) => write!(f, "YAML parsing error: {}", msg),
            RuleError::SemgrepError(msg) => write!(f, "Semgrep validation error: {}", msg),
            RuleError::SemgrepNotFound => write!(f, "semgrep binary not found in PATH"),
            RuleError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for RuleError {}

/// Validate a semgrep rule YAML
///
/// Writes the YAML to a temp file and runs `semgrep --validate --config <tmpfile>`
/// Returns Ok(()) if validation passes, Err(RuleError) otherwise
pub fn validate_rule(rule_yaml: &str) -> Result<(), RuleError> {
    // Check if semgrep is available
    if which::which("semgrep").is_err() {
        return Err(RuleError::SemgrepNotFound);
    }

    // Write YAML to temp file
    let mut temp_file = NamedTempFile::new()
        .map_err(|e| RuleError::IoError(format!("Failed to create temp file: {}", e)))?;

    temp_file
        .write_all(rule_yaml.as_bytes())
        .map_err(|e| RuleError::IoError(format!("Failed to write to temp file: {}", e)))?;

    // Run semgrep --validate
    let output = Command::new("semgrep")
        .arg("--validate")
        .arg("--config")
        .arg(temp_file.path())
        .output()
        .map_err(|e| RuleError::IoError(format!("Failed to run semgrep: {}", e)))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let error_msg = if !stderr.is_empty() {
            stderr.to_string()
        } else {
            stdout.to_string()
        };

        Err(RuleError::SemgrepError(error_msg.trim().to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_yaml_missing_rules_key() {
        // Valid YAML but missing "rules:" key - should fail semgrep validation
        let invalid_rule = r#"id: test-rule
pattern: $X
message: Test
languages:
  - python
severity: WARNING
"#;

        let result = validate_rule(invalid_rule);
        // If semgrep is available, this should fail because it's not a valid semgrep rule
        // If semgrep is not available, this should return SemgrepNotFound
        match result {
            Err(RuleError::SemgrepNotFound) => {
                // semgrep not installed, test is skipped
                println!("semgrep not installed, skipping validation test");
            }
            Err(_) => {
                // Expected: invalid semgrep rule
            }
            Ok(()) => {
                // Unexpected: should have failed
                panic!("Expected validation to fail for invalid rule");
            }
        }
    }

    #[test]
    fn test_validate_error_display() {
        let err = RuleError::LlmError("test error".to_string());
        assert_eq!(format!("{}", err), "LLM error: test error");

        let err = RuleError::YamlError("invalid yaml".to_string());
        assert_eq!(format!("{}", err), "YAML parsing error: invalid yaml");

        let err = RuleError::SemgrepError("validation failed".to_string());
        assert_eq!(
            format!("{}", err),
            "Semgrep validation error: validation failed"
        );

        let err = RuleError::SemgrepNotFound;
        assert_eq!(format!("{}", err), "semgrep binary not found in PATH");

        let err = RuleError::IoError("io error".to_string());
        assert_eq!(format!("{}", err), "I/O error: io error");
    }

    #[test]
    fn test_validate_rule_empty_string() {
        let result = validate_rule("");
        // Empty string will either fail semgrep validation or return SemgrepNotFound
        match result {
            Err(RuleError::SemgrepNotFound) => {}
            Err(_) => {}
            Ok(()) => panic!("Expected validation to fail for empty input"),
        }
    }

    #[test]
    fn test_validate_rule_with_null_bytes() {
        let rule_with_null = "rules:\n  - id: test\x00null";
        let result = validate_rule(rule_with_null);
        match result {
            Err(RuleError::SemgrepNotFound) => {}
            Err(_) => {}
            Ok(()) => panic!("Expected validation to fail for input with null bytes"),
        }
    }

    #[test]
    fn test_validate_rule_with_unicode() {
        let rule_with_unicode = r#"rules:
  - id: test-unicode-测试
    message: "Unicode: émojis 🚀, cañón"
    languages:
      - python
"#;
        let result = validate_rule(rule_with_unicode);
        match result {
            Err(RuleError::SemgrepNotFound) => {}
            Err(_) => {}
            Ok(()) => {}
        }
    }

    #[test]
    fn test_validate_rule_very_long_input() {
        let long_yaml = format!("rules:\n{}", "  - id: test-rule-\n".repeat(1000));
        let result = validate_rule(&long_yaml);
        // Should not panic, may succeed or fail depending on semgrep
        match result {
            Err(RuleError::SemgrepNotFound) => {}
            _ => {}
        }
    }

    #[test]
    fn test_rule_error_source_returns_none() {
        let err = RuleError::LlmError("test".to_string());
        assert!(std::error::Error::source(&err).is_none());

        let err = RuleError::YamlError("test".to_string());
        assert!(std::error::Error::source(&err).is_none());

        let err = RuleError::SemgrepError("test".to_string());
        assert!(std::error::Error::source(&err).is_none());

        let err = RuleError::SemgrepNotFound;
        assert!(std::error::Error::source(&err).is_none());

        let err = RuleError::IoError("test".to_string());
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn test_rule_error_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<RuleError>();
        assert_sync::<RuleError>();
    }

    #[test]
    fn test_rule_error_clone() {
        let err1 = RuleError::LlmError("test error".to_string());
        let err2 = err1.clone();
        assert_eq!(format!("{}", err1), format!("{}", err2));

        let err1 = RuleError::SemgrepNotFound;
        let err2 = err1.clone();
        assert_eq!(format!("{}", err1), format!("{}", err2));
    }
}
