//! Semgrep rule validation using `semgrep --validate` subprocess

use serde_yaml::Value;
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
    // Pre-validation: parse YAML and check for dangerous constructs
    let parsed: Value = serde_yaml::from_str(rule_yaml)
        .map_err(|e| RuleError::YamlError(format!("Invalid YAML: {}", e)))?;

    // Check for dangerous type tags (!! which could trigger unexpected type coercion)
    check_for_dangerous_tags(&parsed, "")?;

    // Verify top-level structure: must have a `rules` key that is a sequence
    if let Value::Mapping(map) = &parsed {
        if let Some(rules_value) = map.get(Value::String("rules".to_string())) {
            if !matches!(rules_value, Value::Sequence(_)) {
                return Err(RuleError::YamlError(
                    "YAML must have a top-level 'rules' key that is a sequence".to_string(),
                ));
            }
        } else {
            return Err(RuleError::YamlError(
                "YAML must have a top-level 'rules' key".to_string(),
            ));
        }
    } else {
        return Err(RuleError::YamlError(
            "YAML must be an object at the top level".to_string(),
        ));
    }

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

/// Recursively check for dangerous YAML type tags that could trigger unexpected type coercion
fn check_for_dangerous_tags(value: &Value, path: &str) -> Result<(), RuleError> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(s) => {
            if s.contains("!!") {
                return Err(RuleError::YamlError(format!(
                    "Dangerous type tag detected at path '{}': type tags can trigger unexpected type coercion",
                    path
                )));
            }
            Ok(())
        }
        Value::Sequence(seq) => {
            for (i, item) in seq.iter().enumerate() {
                let item_path = if path.is_empty() {
                    format!("[{}]", i)
                } else {
                    format!("{}.{}", path, i)
                };
                check_for_dangerous_tags(item, &item_path)?;
            }
            Ok(())
        }
        Value::Mapping(map) => {
            for (key, val) in map.iter() {
                let key_str = key.as_str().unwrap_or("<invalid key>");
                let item_path = if path.is_empty() {
                    key_str.to_string()
                } else {
                    format!("{}.{}", path, key_str)
                };

                // Check if the key contains type tag markers
                if key_str.contains("!!") {
                    return Err(RuleError::YamlError(format!(
                        "Dangerous type tag detected at path '{}': type tags can trigger unexpected type coercion",
                        item_path
                    )));
                }

                check_for_dangerous_tags(val, &item_path)?;
            }
            Ok(())
        }
        Value::Tagged(_) => Err(RuleError::YamlError(
            "Dangerous type tag detected: explicit YAML tags can trigger unexpected type coercion"
                .to_string(),
        )),
    }
}
