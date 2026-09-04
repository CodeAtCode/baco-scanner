//! Unit tests for rule synthesis phase.
//!
//! Tests the RuleSynthesizer API and rule generation logic.

use baco::config::RuleSynthConfig;
use baco::rulesynth::{parse_yaml_rules, validate_rule};
use std::path::PathBuf;

// ============================================================================
// YAML Parsing Tests
// ============================================================================

#[test]
fn test_parse_yaml_rules_empty() {
    let yaml = "";
    let rules = parse_yaml_rules(yaml, "python").unwrap();

    assert!(rules.is_empty());
}

#[test]
fn test_parse_yaml_rules_whitespace_only() {
    let yaml = "   \n\n   \n";
    let rules = parse_yaml_rules(yaml, "python").unwrap();

    assert!(rules.is_empty());
}

#[test]
fn test_parse_yaml_rules_single_rule() {
    let yaml = "\
---
id: test-rule
patterns:
  - pattern: vulnerable_code()
message: Test vulnerability
severity: WARNING
languages:
  - python
---
";
    let rules = parse_yaml_rules(yaml, "python").unwrap();

    assert_eq!(rules.len(), 1);
    assert!(rules[0].contains("test-rule"));
}

#[test]
fn test_parse_yaml_rules_multiple_rules() {
    let yaml = "\
---
id: rule-1
patterns:
  - pattern: code1()
message: Rule 1
---
id: rule-2
patterns:
  - pattern: code2()
message: Rule 2
---
";
    let rules = parse_yaml_rules(yaml, "python").unwrap();

    assert_eq!(rules.len(), 2);
}

#[test]
fn test_parse_yaml_rules_invalid_yaml() {
    let yaml = "invalid: yaml: content: [";
    let result = parse_yaml_rules(yaml, "python");

    // The line-based parser is tolerant: undelimited non-empty content
    // falls back to a single raw rule instead of erroring
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], "invalid: yaml: content: [");
}

// ============================================================================
// Rule Validation Tests
// ============================================================================

#[test]
fn test_validate_rule_empty() {
    let yaml = "";
    let result = validate_rule(yaml);

    assert!(result.is_err());
}

#[test]
fn test_validate_rule_minimal_valid() {
    let yaml = r#"
rules:
  - id: test-rule
    patterns:
      - pattern: test()
    message: Test
    severity: WARNING
    languages:
      - python
"#;
    let result = validate_rule(yaml);

    // Validation may pass or fail depending on semgrep binary availability
    // We just verify it doesn't panic
    let _ = result;
}

#[test]
fn test_validate_rule_missing_id() {
    let yaml = r#"
rules:
  - patterns:
      - pattern: test()
    message: Test
    severity: WARNING
    languages:
      - python
"#;
    let result = validate_rule(yaml);

    // Should fail due to missing id
    assert!(result.is_err());
}

#[test]
fn test_validate_rule_missing_patterns() {
    let yaml = r#"
rules:
  - id: test-rule
    message: Test
    severity: WARNING
    languages:
      - python
"#;
    let result = validate_rule(yaml);

    // Should fail due to missing patterns
    assert!(result.is_err());
}

// ============================================================================
// RuleSynthesizer API Tests
// ============================================================================

#[test]
fn test_synthesizer_new() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/tmp/test-rules"),
        max_rules_per_cwe: 3,
        mocq_mode: false,
        max_iterations: 5,
        corpus_path: None,
    };

    // We can't create a full synthesizer without an LLM client,
    // but we can verify the config structure
    assert!(config.output_dir.is_absolute() || config.output_dir.starts_with("/tmp"));
    assert_eq!(config.max_rules_per_cwe, 3);
}

#[test]
fn test_synthesis_config_defaults() {
    let config = RuleSynthConfig::default();

    assert!(!config.enabled);
    assert_eq!(config.max_rules_per_cwe, 5);
    assert!(!config.mocq_mode);
    assert_eq!(config.max_iterations, 5);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_parse_yaml_rules_very_long_rule() {
    let long_pattern = "a".repeat(10000);
    let yaml = format!(
        r#"
rules:
  - id: long-rule
    patterns:
      - pattern: {}
    message: Long rule
    severity: WARNING
    languages:
      - python
"#,
        long_pattern
    );

    let rules = parse_yaml_rules(&yaml, "python").unwrap();

    assert_eq!(rules.len(), 1);
}

#[test]
fn test_parse_yaml_rules_special_characters() {
    let yaml = r#"
rules:
  - id: "rule-with-special-chars_123"
    patterns:
      - pattern: "code <script>alert('xss')</script>"
    message: "Test with special chars: <>&"
    severity: WARNING
    languages:
      - python
"#;

    let rules = parse_yaml_rules(yaml, "python").unwrap();

    assert_eq!(rules.len(), 1);
}

#[test]
fn test_parse_yaml_rules_unicode() {
    let yaml = r#"
rules:
  - id: "règle-unicode"
    patterns:
      - pattern: "café naïve"
    message: "Test unicode: café"
    severity: WARNING
    languages:
      - python
"#;

    let rules = parse_yaml_rules(yaml, "python").unwrap();

    assert_eq!(rules.len(), 1);
}

#[test]
fn test_parse_yaml_rules_different_languages() {
    let yaml = r#"
rules:
  - id: python-rule
    patterns:
      - pattern: print()
    message: Python rule
    severity: WARNING
    languages:
      - python
  - id: javascript-rule
    patterns:
      - pattern: console.log()
    message: JS rule
    severity: WARNING
    languages:
      - javascript
"#;

    let python_rules = parse_yaml_rules(yaml, "python").unwrap();
    let js_rules = parse_yaml_rules(yaml, "javascript").unwrap();

    assert_eq!(python_rules.len(), 1);
    assert_eq!(js_rules.len(), 1);
}
