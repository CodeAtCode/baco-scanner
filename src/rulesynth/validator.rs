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
