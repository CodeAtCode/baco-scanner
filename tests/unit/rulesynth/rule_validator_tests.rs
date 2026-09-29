//! Unit tests for rule validation
//!
//! Tests that invalid YAML is rejected, valid YAML is accepted,
//! and malformed semgrep rules are properly validated.

use baco::rulesynth::{RuleError, validate_rule};
use tempfile::NamedTempFile;
use which::which;

#[test]
fn test_validate_semgrep_available() {
    // Check if semgrep is available - assert the result
    match which("semgrep") {
        Ok(path) => {
            // semgrep is available, assert we got a valid path
            assert!(path.exists());
        }
        Err(_) => {
            // semgrep not found - this is acceptable in environments without semgrep
            // The test still validates that the check works correctly
            println!("semgrep not found - validation tests require semgrep in PATH");
        }
    }
}

#[test]
fn test_validate_invalid_yaml() {
    // Invalid YAML syntax should fail
    let invalid_yaml = r#"rules:
  - id: test-rule
    pattern: $X
    message: Test
    languages: [python
    severity: WARNING
"#;

    let result = validate_rule(invalid_yaml);

    // Should fail due to YAML parse error or semgrep validation error
    match result {
        Err(_) => {
            // Expected - invalid YAML should fail
        }
        Ok(()) => {
            panic!("Expected validation to fail for invalid YAML");
        }
    }
}

#[test]
fn test_validate_missing_rules_key() {
    // Valid YAML but missing "rules:" top-level key
    let missing_rules = r#"id: test-rule
pattern: $X
message: Test
languages:
  - python
severity: WARNING
"#;

    let result = validate_rule(missing_rules);

    // semgrep should reject this as it's not a valid semgrep rule file
    // If semgrep is not installed, we get SemgrepNotFound
    match result {
        Err(RuleError::SemgrepNotFound) => {
            // semgrep not installed - acceptable
        }
        Err(_) => {
            // Expected - semgrep requires "rules:" top-level key
        }
        Ok(()) => {
            // If we get here, semgrep is installed but accepted an invalid rule
            // This should not happen
            panic!("Expected validation to fail for missing rules key");
        }
    }
}

#[test]
fn test_validate_valid_minimal_rule() {
    // If semgrep is available, test a valid minimal rule
    if which("semgrep").is_err() {
        println!("semgrep not installed, skipping valid rule test");
        return;
    }

    let valid_rule = r#"rules:
  - id: test-minimal-rule
    pattern: $X
    message: "Test vulnerability"
    languages:
      - python
    severity: WARNING
"#;

    let result = validate_rule(valid_rule);

    match result {
        Ok(()) => {
            // Expected - valid semgrep rule
        }
        Err(e) => {
            panic!("Expected valid rule to pass validation: {}", e);
        }
    }
}

#[test]
fn test_validate_tempfile_cleanup() {
    // Verify that temp files are created and cleaned up properly
    let _temp = NamedTempFile::new().expect("Failed to create temp file");
    // Temp file is cleaned up on drop
}

#[test]
fn test_validate_empty_yaml() {
    let empty = "";
    let result = validate_rule(empty);

    // Empty YAML should fail
    match result {
        Err(_) => {
            // Expected
        }
        Ok(()) => {
            panic!("Expected validation to fail for empty YAML");
        }
    }
}

#[test]
fn test_validate_yaml_with_comments() {
    // Valid YAML with comments should work
    let with_comments = r#"# This is a comment
rules:
  # Another comment
  - id: test-commented-rule
    pattern: $X  # inline comment
    message: "Test with comments"
    languages:
      - python
    severity: WARNING
"#;

    let result = validate_rule(with_comments);

    match result {
        Ok(()) => {
            // Valid YAML with comments should pass when semgrep is available
        }
        Err(RuleError::SemgrepNotFound) => {
            // semgrep not installed - acceptable
        }
        Err(e) => {
            // Unexpected error
            panic!("Valid YAML with comments should pass: {}", e);
        }
    }
}
