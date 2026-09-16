//! Unit tests for validator module (migrated from inline #[cfg(test)] block)

use baco::rulesynth::{validate_rule, RuleError};

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
    if let Err(RuleError::SemgrepNotFound) = result {}
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
fn test_validate_rule_max_yaml_size() {
    // Test with a very large YAML file (10MB)
    let large_yaml = format!("rules:\n{}", "  - id: test-rule-\n".repeat(100000));
    let result = validate_rule(&large_yaml);
    // Should not panic, may succeed or fail depending on semgrep
    match result {
        Err(RuleError::SemgrepNotFound) => {}
        Err(RuleError::YamlError(_)) => {}
        Err(RuleError::SemgrepError(_)) => {}
        Err(RuleError::LlmError(_)) => {}
        Err(RuleError::IoError(_)) => {}
        Ok(()) => {}
    }
}
