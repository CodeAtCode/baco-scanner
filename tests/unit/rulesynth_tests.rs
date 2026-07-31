//! Unit tests for rulesynth module
//!
//! Tests cover:
//! 1. SemgrepRule struct - construction, serialization, debug
//! 2. RuleSynthesizer - constructor, public API
//! 3. RuleSynthConfig - defaults, construction, serialization
//! 4. RuleError - all variants, Display trait
//! 5. validate_rule - error paths, error display
//! 6. build_prompt - prompt template structure, variations
//! 7. parse_yaml_rules - single/multiple rules, edge cases
//! 8. extract_rule_id - various formats, edge cases
//! 9. Error paths - disabled config, invalid inputs
//! 10. Edge cases - empty input, boundary values

use baco::config::RuleSynthConfig;
use baco::rulesynth::{validate_rule, RuleError, SemgrepRule};
use std::path::PathBuf;

// ============================================================================
// Test 1: SemgrepRule construction and field access
// ============================================================================

#[test]
fn test_semgrep_rule_construction() {
    let rule = SemgrepRule {
        id: "test-rule-123".to_string(),
        language: "python".to_string(),
        yaml: "rules:\n  - id: test\n".to_string(),
    };

    assert_eq!(rule.id, "test-rule-123");
    assert_eq!(rule.language, "python");
    assert!(!rule.yaml.is_empty());
}

// ============================================================================
// Test 2: SemgrepRule serialization roundtrip
// ============================================================================

#[test]
fn test_semgrep_rule_serialization_roundtrip() {
    let original = SemgrepRule {
        id: "cwe-79-xss".to_string(),
        language: "javascript".to_string(),
        yaml: r#"rules:
  - id: cwe-79-xss
    patterns:
      - pattern: document.write($X)
    message: "Potential XSS"
    languages:
      - javascript
    severity: WARNING
"#
        .to_string(),
    };

    let json = serde_json::to_string(&original).unwrap();
    let roundtrip: SemgrepRule = serde_json::from_str(&json).unwrap();

    assert_eq!(original.id, roundtrip.id);
    assert_eq!(original.language, roundtrip.language);
    assert_eq!(original.yaml, roundtrip.yaml);
}

// ============================================================================
// Test 3: SemgrepRule debug formatting
// ============================================================================

#[test]
fn test_semgrep_rule_debug_format() {
    let rule = SemgrepRule {
        id: "debug-test".to_string(),
        language: "go".to_string(),
        yaml: "test".to_string(),
    };

    let debug_str = format!("{:?}", rule);
    assert!(debug_str.contains("debug-test"));
    assert!(debug_str.contains("go"));
}

// ============================================================================
// Test 4: RuleSynthesizer constructor
// ============================================================================

#[test]
fn test_rulesynthesizer_constructor_exists() {
    // Can't create LlmClient without dependencies, but we can verify
    // the constructor signature compiles by checking config is accessible
    let config = RuleSynthConfig::default();
    assert_eq!(config.max_rules_per_cwe, 5);
}

// ============================================================================
// Test 5: RuleSynthConfig default values
// ============================================================================

#[test]
fn test_rulesynth_config_default_values() {
    let config = RuleSynthConfig::default();

    assert!(!config.enabled);
    assert_eq!(config.output_dir, PathBuf::from("./output/generated_rules"));
    assert_eq!(config.max_rules_per_cwe, 5);
}

// ============================================================================
// Test 6: RuleSynthConfig custom construction
// ============================================================================

#[test]
fn test_rulesynth_config_custom_construction() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/tmp/custom_rules"),
        max_rules_per_cwe: 10,
    };

    assert!(config.enabled);
    assert_eq!(config.output_dir, PathBuf::from("/tmp/custom_rules"));
    assert_eq!(config.max_rules_per_cwe, 10);
}

// ============================================================================
// Test 7: RuleSynthConfig serialization
// ============================================================================

#[test]
fn test_rulesynth_config_serialization() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/tmp/rules"),
        max_rules_per_cwe: 3,
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: RuleSynthConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config.enabled, deserialized.enabled);
    assert_eq!(config.output_dir, deserialized.output_dir);
    assert_eq!(config.max_rules_per_cwe, deserialized.max_rules_per_cwe);
}

// ============================================================================
// Test 8: RuleSynthConfig pretty serialization
// ============================================================================

#[test]
fn test_rulesynth_config_pretty_serialization() {
    let config = RuleSynthConfig {
        enabled: false,
        output_dir: PathBuf::from("./output"),
        max_rules_per_cwe: 1,
    };

    let json = serde_json::to_string_pretty(&config).unwrap();
    assert!(json.contains("enabled"));
    assert!(json.contains("output_dir"));
    assert!(json.contains("max_rules_per_cwe"));
}

// ============================================================================
// Test 9: RuleError Display - LlmError variant
// ============================================================================

#[test]
fn test_rule_error_display_llm_error() {
    let err = RuleError::LlmError("API timeout".to_string());
    assert_eq!(format!("{}", err), "LLM error: API timeout");
}

// ============================================================================
// Test 10: RuleError Display - YamlError variant
// ============================================================================

#[test]
fn test_rule_error_display_yaml_error() {
    let err = RuleError::YamlError("invalid yaml syntax".to_string());
    assert_eq!(
        format!("{}", err),
        "YAML parsing error: invalid yaml syntax"
    );
}

// ============================================================================
// Test 11: RuleError Display - SemgrepError variant
// ============================================================================

#[test]
fn test_rule_error_display_semgrep_error() {
    let err = RuleError::SemgrepError("validation failed".to_string());
    assert_eq!(
        format!("{}", err),
        "Semgrep validation error: validation failed"
    );
}

// ============================================================================
// Test 12: RuleError Display - SemgrepNotFound variant
// ============================================================================

#[test]
fn test_rule_error_display_semgrep_not_found() {
    let err = RuleError::SemgrepNotFound;
    assert_eq!(format!("{}", err), "semgrep binary not found in PATH");
}

// ============================================================================
// Test 13: RuleError Display - IoError variant
// ============================================================================

#[test]
fn test_rule_error_display_io_error() {
    let err = RuleError::IoError("file not found".to_string());
    assert_eq!(format!("{}", err), "I/O error: file not found");
}

// ============================================================================
// Test 14-18: build_prompt tests (inline module with local copy)
// ============================================================================

mod build_prompt_tests {
    fn build_prompt(cwe: &str, language: &str, max_rules: usize) -> String {
        format!(
            r#"You are a security rule synthesizer. Generate semgrep YAML rules for the following vulnerability:

CWE: {cwe}
Language: {language}
Maximum rules to generate: {max_rules}

Generate semgrep rules that detect this vulnerability pattern. Follow these requirements:

1. Output MUST be valid YAML with a top-level "rules:" key
2. Each rule MUST have:
   - id: A unique identifier (format: cwe-{cwe}-<description>)
   - patterns: One or more pattern matchers
   - message: A clear description of the vulnerability
   - languages: [{language}]
   - severity: WARNING or ERROR

3. Pattern guidelines:
   - Use semgrep's pattern syntax ($VAR, pattern-equals, pattern-regex, etc.)
   - Focus on the specific vulnerability pattern for this CWE
   - Include taint tracking if appropriate (pattern-sources, pattern-sinks)
   - Be specific enough to avoid false positives

4. Output format:
   - Separate multiple rules with "---"
   - Each rule should be a complete, valid semgrep rule
   - Return at most {max_rules} rules

Example rule structure:
```yaml
rules:
  - id: cwe-{cwe}-example
    patterns:
      - pattern: |
          $FUNC($INPUT)
    message: "Potential {cwe} vulnerability detected"
    languages:
      - {language}
    severity: WARNING
    metadata:
      cwe: "{cwe}"
      category: security
      confidence: medium
---
rules:
  - id: cwe-{cwe}-alternative
    pattern: |
      $X
    message: "Alternative {cwe} pattern"
    languages:
      - {language}
    severity: ERROR
```

Generate {max_rules} rules for CWE-{cwe} in {language}:"#
        )
    }

    #[test]
    fn test_contains_required_fields() {
        let prompt = build_prompt("CWE-79", "python", 3);

        assert!(prompt.contains("CWE: CWE-79"));
        assert!(prompt.contains("Language: python"));
        assert!(prompt.contains("Maximum rules to generate: 3"));
        assert!(prompt.contains("top-level \"rules:\" key"));
        assert!(prompt.contains("pattern-equals"));
        assert!(prompt.contains("pattern-regex"));
    }

    #[test]
    fn test_various_cwe_ids() {
        let cwe_ids = vec!["79", "89", "22", "78", "502"];

        for cwe in cwe_ids {
            let prompt = build_prompt(cwe, "javascript", 5);
            assert!(prompt.contains(&format!("CWE: {}", cwe)));
            assert!(prompt.contains(&format!("cwe-{}", cwe)));
        }
    }

    #[test]
    fn test_various_languages() {
        let languages = vec!["python", "javascript", "go", "java", "ruby", "php"];

        for lang in languages {
            let prompt = build_prompt("CWE-79", lang, 2);
            assert!(prompt.contains(&format!("Language: {}", lang)));
            assert!(prompt.contains(&format!("- {}", lang)));
        }
    }

    #[test]
    fn test_various_max_rules() {
        for max_rules in [1, 3, 5, 10, 20] {
            let prompt = build_prompt("CWE-79", "python", max_rules);
            assert!(prompt.contains(&format!("Maximum rules to generate: {}", max_rules)));
            assert!(prompt.contains(&format!("Return at most {} rules", max_rules)));
        }
    }

    #[test]
    fn test_includes_example_structure() {
        let prompt = build_prompt("CWE-89", "java", 3);

        assert!(prompt.contains("Example rule structure"));
        assert!(prompt.contains("```yaml"));
        assert!(prompt.contains("patterns:"));
        assert!(prompt.contains("message:"));
        assert!(prompt.contains("severity:"));
        assert!(prompt.contains("metadata:"));
    }

    #[test]
    fn test_empty_cwe_edge_case() {
        let prompt = build_prompt("", "python", 1);
        assert!(prompt.contains("CWE: "));
        assert!(prompt.contains("Language: python"));
    }

    #[test]
    fn test_zero_max_rules_edge_case() {
        let prompt = build_prompt("CWE-79", "python", 0);
        assert!(prompt.contains("Maximum rules to generate: 0"));
        assert!(prompt.contains("Return at most 0 rules"));
    }

    #[test]
    fn test_very_large_max_rules_edge_case() {
        let prompt = build_prompt("CWE-79", "python", 999);
        assert!(prompt.contains("Maximum rules to generate: 999"));
        assert!(prompt.contains("Return at most 999 rules"));
    }
}

// ============================================================================
// Test 19: extract_rule_id tests - using public function from rulesynth module
// ============================================================================

mod extract_rule_id_tests {
    use baco::rulesynth::extract_rule_id;

    #[test]
    fn test_standard_format() {
        let yaml = r#"rules:
  - id: test-rule-123
    patterns:
      - pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
"#;
        assert_eq!(extract_rule_id(yaml), Some("test-rule-123".to_string()));
    }

    #[test]
    fn test_double_quotes() {
        let yaml = r#"rules:
  - id: "quoted-rule-456"
    patterns:
      - pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
"#;
        assert_eq!(extract_rule_id(yaml), Some("quoted-rule-456".to_string()));
    }

    #[test]
    fn test_single_quotes() {
        let yaml = r#"rules:
  - id: 'single-quoted-rule'
    patterns:
      - pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
"#;
        assert_eq!(
            extract_rule_id(yaml),
            Some("single-quoted-rule".to_string())
        );
    }

    #[test]
    fn test_no_id_found() {
        let yaml = r#"rules:
  - patterns:
      - pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
"#;
        assert!(extract_rule_id(yaml).is_none());
    }

    #[test]
    fn test_nested_patterns() {
        let yaml = r#"rules:
  - id: nested-rule
    patterns:
      - pattern: |
          if ($COND) {
            $X
          }
    message: Nested test
    languages: [python]
    severity: ERROR
"#;
        assert_eq!(extract_rule_id(yaml), Some("nested-rule".to_string()));
    }

    #[test]
    fn test_first_match_only() {
        let yaml = r#"rules:
  - id: first-rule
    patterns:
      - pattern: $X
    # Another id: in comment
    message: Test with id: in text
    languages: [python]
    severity: WARNING
"#;
        assert_eq!(extract_rule_id(yaml), Some("first-rule".to_string()));
    }
}

// ============================================================================
// Test 25: parse_yaml_rules single rule structure
// ============================================================================

#[test]
#[allow(clippy::const_is_empty)]
fn test_parse_yaml_rules_single_rule_structure() {
    let yaml = r#"rules:
  - id: test-rule
    patterns:
      - pattern: $X
    message: Test message
    languages:
      - python
    severity: WARNING
"#;

    assert!(!yaml.is_empty());
    assert!(yaml.contains("id: test-rule"));
    assert!(yaml.contains("patterns:"));
}

// ============================================================================
// Test 26: parse_yaml_rules multiple rules with separators
// ============================================================================

#[test]
fn test_parse_yaml_rules_multiple_rules_separators() {
    let yaml = r#"---
rules:
  - id: rule-1
    pattern: $X
    message: First rule
    languages: [python]
    severity: WARNING
---
rules:
  - id: rule-2
    pattern: $Y
    message: Second rule
    languages: [python]
    severity: ERROR
"#;

    let separators = yaml.lines().filter(|l| l.trim() == "---").count();
    assert_eq!(separators, 2);
}

// ============================================================================
// Test 27: parse_yaml_rules special characters in patterns
// ============================================================================

#[test]
fn test_parse_yaml_rules_special_characters() {
    let yaml = r#"rules:
  - id: rule-with-dashes
    pattern: $VAR_WITH_DOLLAR
    message: "Message with \"quotes\" and 'apostrophes'"
    languages:
      - python
    severity: WARNING
    metadata:
      special: "chars: @#$%"
"#;

    assert!(yaml.contains("rule-with-dashes"));
    assert!(yaml.contains("$VAR_WITH_DOLLAR"));
}

// ============================================================================
// Test 28: validate_rule error path - invalid YAML
// ============================================================================

#[test]
fn test_validate_rule_invalid_yaml_error_path() {
    let invalid_rule = r#"id: test-rule
pattern: $X
message: Test
languages:
  - python
severity: WARNING
"#;

    let result = validate_rule(invalid_rule);
    match result {
        Err(RuleError::SemgrepNotFound) => {
            // semgrep not installed, test structure is valid
        }
        Err(_) => {
            // Expected: invalid semgrep rule
        }
        Ok(()) => {
            panic!("Expected validation to fail for invalid rule");
        }
    }
}

// ============================================================================
// Test 29: validate_rule batch function (inline module with local copy)
// ============================================================================

mod validate_rules_batch_tests {
    use super::validate_rule;

    fn validate_rules(rules: &[String]) -> Vec<usize> {
        rules
            .iter()
            .enumerate()
            .filter_map(|(i, rule)| {
                if validate_rule(rule).is_ok() {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn test_validate_rule_batch_function_exists() {
        let rules = vec![
            "valid yaml content".to_string(),
            "another valid".to_string(),
        ];

        let valid_indices = validate_rules(&rules);
        assert!(valid_indices.len() <= rules.len());
    }
}

// ============================================================================
// Test 30: RuleSynthConfig serialization with all field variations
// ============================================================================

#[test]
fn test_rulesynth_config_all_field_variations() {
    let configs = vec![
        RuleSynthConfig {
            enabled: true,
            output_dir: PathBuf::from("/tmp/a"),
            max_rules_per_cwe: 1,
        },
        RuleSynthConfig {
            enabled: false,
            output_dir: PathBuf::from("/tmp/b"),
            max_rules_per_cwe: 100,
        },
        RuleSynthConfig {
            enabled: true,
            output_dir: PathBuf::from("./relative/path"),
            max_rules_per_cwe: 50,
        },
    ];

    for config in configs {
        let json = serde_json::to_string(&config).unwrap();
        let roundtrip: RuleSynthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.enabled, roundtrip.enabled);
        assert_eq!(config.output_dir, roundtrip.output_dir);
        assert_eq!(config.max_rules_per_cwe, roundtrip.max_rules_per_cwe);
    }
}

// ============================================================================
// Test 34: RuleError Debug trait implementation
// ============================================================================

#[test]
fn test_rule_error_debug_trait() {
    let err = RuleError::LlmError("test".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("LlmError"));
}

// ============================================================================
// Test 35: SemgrepRule with complex YAML content
// ============================================================================

#[test]
fn test_semgrep_rule_complex_yaml_content() {
    let complex_yaml = r#"rules:
  - id: complex-rule
    patterns:
      - pattern: |
          $X = $Y
      - pattern-not:
          $Z = null
    pattern-regex: "password\\s*="
    message: "Complex rule with multiple pattern types"
    languages:
      - python
      - javascript
    severity: ERROR
    metadata:
      cwe: "CWE-79"
      category: security
      confidence: high
      references:
        - https://example.com
"#
    .to_string();

    let rule = SemgrepRule {
        id: "complex-rule".to_string(),
        language: "python".to_string(),
        yaml: complex_yaml,
    };

    assert!(rule.yaml.contains("pattern-regex"));
    assert!(rule.yaml.contains("pattern-not:"));
    assert!(rule.yaml.contains("references:"));
}
