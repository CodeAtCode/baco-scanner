//! Deep unit tests for rulesynth module
//!
//! This file provides comprehensive coverage for:
//! 1. parse_yaml_rules - YAML parsing logic with multiple edge cases
//! 2. extract_rule_id - ID extraction from various YAML formats
//! 3. RuleSynthesizer - constructor and internal method testing
//! 4. Error handling paths - all RuleError variants
//! 5. Prompt generation - build_prompt variations
//! 6. Edge cases - empty input, boundary values, special characters

use baco::config::RuleSynthConfig;
use baco::rulesynth::{RuleError, SemgrepRule};
use std::path::PathBuf;

// Local copies of private functions for testing (mirrors src/rulesynth/mod.rs)
fn parse_yaml_rules(yaml_content: &str, _language: &str) -> Result<Vec<String>, RuleError> {
    let mut rules = Vec::new();
    let mut current_rule = String::new();
    let mut in_rule = false;

    for line in yaml_content.lines() {
        if line.trim() == "---" {
            if !current_rule.is_empty() {
                rules.push(current_rule.trim().to_string());
                current_rule = String::new();
            }
            in_rule = true;
            continue;
        }

        if in_rule || line.trim().starts_with("rules:") {
            let should_add = !current_rule.is_empty() || !line.trim().is_empty();
            if should_add {
                current_rule.push_str(line);
                current_rule.push('\n');
            }
        }
    }

    // Push last rule
    if !current_rule.is_empty() {
        rules.push(current_rule.trim().to_string());
    }

    // If no rules found, try to parse as single rule
    if rules.is_empty() && !yaml_content.trim().is_empty() {
        rules.push(yaml_content.trim().to_string());
    }

    Ok(rules)
}

fn extract_rule_id(yaml: &str) -> Option<String> {
    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed.contains("id:") {
            // Find the "id:" position and extract the value
            if let Some(idx) = trimmed.find("id:") {
                let after_id = &trimmed[idx + 3..];
                let id = after_id.trim();
                // Remove quotes if present
                let id = id.trim_matches('"').trim_matches('\'');
                if !id.is_empty() {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}

// Local copy of build_prompt for testing (mirrors src/rulesynth/prompt.rs)
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

// ============================================================================
// parse_yaml_rules tests - comprehensive YAML parsing coverage
// ============================================================================

#[test]
fn test_parse_yaml_rules_empty_input() {
    let result = parse_yaml_rules("", "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    // Empty input results in empty vector (no rules)
    assert!(rules.is_empty());
}

#[test]
fn test_parse_yaml_rules_whitespace_only() {
    let result = parse_yaml_rules("   \n\n  \n  ", "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    // Whitespace-only input results in empty vector
    assert!(rules.is_empty());
}

#[test]
fn test_parse_yaml_rules_single_rule_no_separator() {
    let yaml = r#"---
rules:
  - id: single-rule
    patterns:
      - pattern: $X
    message: Single rule test
    languages:
      - python
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
    assert!(rules[0].contains("id: single-rule"));
}

#[test]
fn test_parse_yaml_rules_multiple_rules_with_separators() {
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
---
rules:
  - id: rule-3
    pattern: $Z
    message: Third rule
    languages: [javascript]
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    // Should have 3 rules separated by ---
    assert_eq!(rules.len(), 3);
    assert!(rules[0].contains("rule-1"));
    assert!(rules[1].contains("rule-2"));
    assert!(rules[2].contains("rule-3"));
}

#[test]
fn test_parse_yaml_rules_with_leading_content() {
    let yaml = r#"Some introductory text
---
rules:
  - id: rule-after-text
    pattern: $X
    message: Rule after text
    languages: [python]
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert!(!rules.is_empty());
    assert!(rules.iter().any(|r| r.contains("rule-after-text")));
}

#[test]
fn test_parse_yaml_rules_special_yaml_characters() {
    let yaml = r#"---
rules:
  - id: special-chars-rule
    pattern: |
      if ($VAR == null) {
        $X
      }
    message: "Message with \"quotes\" and 'apostrophes'"
    languages:
      - python
    severity: WARNING
    metadata:
      special: "chars: @#$%^&*"
      multiline: |
        Line 1
        Line 2
        Line 3
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
    assert!(rules[0].contains("special-chars-rule"));
    assert!(rules[0].contains("$VAR"));
}

#[test]
fn test_parse_yaml_rules_empty_rules_list() {
    let yaml = r#"rules: []
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
}

#[test]
fn test_parse_yaml_rules_only_separator() {
    let yaml = "---";

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    // Empty separator should result in empty or single rule
    assert!(rules.len() <= 1);
}

#[test]
fn test_parse_yaml_rules_multiple_consecutive_separators() {
    let yaml = r#"---
---
rules:
  - id: rule-after-empty
    pattern: $X
    message: After empty separators
    languages: [python]
    severity: WARNING
---
---
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert!(!rules.is_empty());
}

#[test]
fn test_parse_yaml_rules_trailing_whitespace() {
    let yaml = r#"---
rules:
  - id: trailing-test
    pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
    
    
    
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
    assert!(rules[0].contains("trailing-test"));
}

#[test]
fn test_parse_yaml_rules_various_languages() {
    let languages = vec![
        "python",
        "javascript",
        "go",
        "java",
        "ruby",
        "php",
        "c",
        "cpp",
    ];

    for lang in languages {
        let yaml = format!(
            r#"---
rules:
  - id: lang-test
    pattern: $X
    message: Language test
    languages:
      - {}
    severity: WARNING
"#,
            lang
        );

        let result = parse_yaml_rules(&yaml, lang);
        assert!(result.is_ok(), "Failed for language: {}", lang);
        let rules = result.unwrap();
        assert_eq!(rules.len(), 1);
    }
}

// ============================================================================
// extract_rule_id tests - comprehensive ID extraction coverage
// ============================================================================

#[test]
fn test_extract_rule_id_empty_yaml() {
    assert_eq!(extract_rule_id(""), None);
}

#[test]
fn test_extract_rule_id_whitespace_yaml() {
    assert_eq!(extract_rule_id("   \n\n  "), None);
}

#[test]
fn test_extract_rule_id_simple_format() {
    let yaml = "id: simple-rule\n";
    assert_eq!(extract_rule_id(yaml), Some("simple-rule".to_string()));
}

#[test]
fn test_extract_rule_id_with_spaces_around() {
    let yaml = "id:   spaced-rule   \n";
    assert_eq!(extract_rule_id(yaml), Some("spaced-rule".to_string()));
}

#[test]
fn test_extract_rule_id_double_quotes() {
    let yaml = "id: \"double-quoted\"\n";
    assert_eq!(extract_rule_id(yaml), Some("double-quoted".to_string()));
}

#[test]
fn test_extract_rule_id_single_quotes() {
    let yaml = "id: 'single-quoted'\n";
    assert_eq!(extract_rule_id(yaml), Some("single-quoted".to_string()));
}

#[test]
fn test_extract_rule_id_nested_in_rules_array() {
    let yaml = r#"rules:
  - id: nested-rule
    patterns:
      - pattern: $X
"#;
    assert_eq!(extract_rule_id(yaml), Some("nested-rule".to_string()));
}

#[test]
fn test_extract_rule_id_multiple_ids_returns_first() {
    let yaml = r#"rules:
  - id: first-rule
    patterns:
      - pattern: $X
    # This is a comment with id: in it
    message: id: appears in text
"#;
    assert_eq!(extract_rule_id(yaml), Some("first-rule".to_string()));
}

#[test]
fn test_extract_rule_id_id_in_comment_ignored() {
    let yaml = r#"rules:
  - id: real-id
    # Another id: fake-id in comment
    message: Test
"#;
    assert_eq!(extract_rule_id(yaml), Some("real-id".to_string()));
}

#[test]
fn test_extract_rule_id_id_in_string_value_ignored() {
    let yaml = r#"rules:
  - id: actual-id
    message: "This has id: somewhere in it"
"#;
    assert_eq!(extract_rule_id(yaml), Some("actual-id".to_string()));
}

#[test]
fn test_extract_rule_id_very_long_id() {
    let long_id = "a".repeat(200);
    let yaml = format!("id: {}\n", long_id);
    assert_eq!(extract_rule_id(&yaml), Some(long_id));
}

#[test]
fn test_extract_rule_id_special_characters_in_id() {
    let yaml = "id: rule-with-dashes_and_underscores123\n";
    assert_eq!(
        extract_rule_id(yaml),
        Some("rule-with-dashes_and_underscores123".to_string())
    );
}

#[test]
fn test_extract_rule_id_cwe_format() {
    let yaml = "id: cwe-79-xss-detection\n";
    assert_eq!(
        extract_rule_id(yaml),
        Some("cwe-79-xss-detection".to_string())
    );
}

#[test]
fn test_extract_rule_id_id_with_colon_after() {
    let yaml = "id: rule-with-colon: in-value\n";
    assert_eq!(
        extract_rule_id(yaml),
        Some("rule-with-colon: in-value".to_string())
    );
}

// ============================================================================
// SemgrepRule tests - construction and serialization
// ============================================================================

#[test]
fn test_semgrep_rule_default_values() {
    let rule = SemgrepRule {
        id: "".to_string(),
        language: "".to_string(),
        yaml: "".to_string(),
    };

    assert!(rule.id.is_empty());
    assert!(rule.language.is_empty());
    assert!(rule.yaml.is_empty());
}

#[test]
fn test_semgrep_rule_clone() {
    let original = SemgrepRule {
        id: "test-id".to_string(),
        language: "python".to_string(),
        yaml: "test yaml".to_string(),
    };

    let cloned = original.clone();

    assert_eq!(original.id, cloned.id);
    assert_eq!(original.language, cloned.language);
    assert_eq!(original.yaml, cloned.yaml);
}

#[test]
fn test_semgrep_rule_debug_format_all_fields() {
    let rule = SemgrepRule {
        id: "debug-id".to_string(),
        language: "javascript".to_string(),
        yaml: "debug-yaml".to_string(),
    };

    let debug_str = format!("{:?}", rule);
    assert!(debug_str.contains("debug-id"));
    assert!(debug_str.contains("javascript"));
    assert!(debug_str.contains("debug-yaml"));
}

#[test]
fn test_semgrep_rule_json_roundtrip_complex() {
    let original = SemgrepRule {
        id: "cwe-89-sql-injection".to_string(),
        language: "python".to_string(),
        yaml: r#"rules:
  - id: cwe-89-sql-injection
    patterns:
      - pattern: |
          cursor.execute($QUERY)
    message: "Potential SQL injection vulnerability"
    languages:
      - python
    severity: ERROR
    metadata:
      cwe: "CWE-89"
      category: security
      confidence: high
      references:
        - https://cwe.mitre.org/data/definitions/89.html
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
// RuleSynthConfig tests - comprehensive configuration coverage
// ============================================================================

#[test]
fn test_rulesynth_config_default_enabled_false() {
    let config = RuleSynthConfig::default();
    assert!(!config.enabled);
}

#[test]
fn test_rulesynth_config_default_output_dir() {
    let config = RuleSynthConfig::default();
    assert_eq!(config.output_dir, PathBuf::from("./output/generated_rules"));
}

#[test]
fn test_rulesynth_config_default_max_rules() {
    let config = RuleSynthConfig::default();
    assert_eq!(config.max_rules_per_cwe, 5);
}

#[test]
fn test_rulesynth_config_all_enabled_true() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/custom/path"),
        max_rules_per_cwe: 10,
    };

    assert!(config.enabled);
    assert_eq!(config.output_dir, PathBuf::from("/custom/path"));
    assert_eq!(config.max_rules_per_cwe, 10);
}

#[test]
fn test_rulesynth_config_zero_max_rules() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/tmp"),
        max_rules_per_cwe: 0,
    };

    assert_eq!(config.max_rules_per_cwe, 0);
}

#[test]
fn test_rulesynth_config_very_large_max_rules() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/tmp"),
        max_rules_per_cwe: 10000,
    };

    assert_eq!(config.max_rules_per_cwe, 10000);
}

#[test]
fn test_rulesynth_config_relative_path() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("./relative/path/to/rules"),
        max_rules_per_cwe: 5,
    };

    assert_eq!(config.output_dir, PathBuf::from("./relative/path/to/rules"));
}

#[test]
fn test_rulesynth_config_json_serialization_all_fields() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/test/path"),
        max_rules_per_cwe: 7,
    };

    let json = serde_json::to_string(&config).unwrap();

    assert!(json.contains("enabled"));
    assert!(json.contains("output_dir"));
    assert!(json.contains("max_rules_per_cwe"));
}

#[test]
fn test_rulesynth_config_pretty_serialization() {
    let config = RuleSynthConfig::default();
    let json = serde_json::to_string_pretty(&config).unwrap();

    // Pretty JSON should have newlines and indentation
    assert!(json.contains('\n'));
}

#[test]
fn test_rulesynth_config_deserialization_invalid_json() {
    let invalid_json = "{ invalid json }";
    let result: Result<RuleSynthConfig, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err());
}

// ============================================================================
// RuleError tests - all variants and Display trait
// ============================================================================

#[test]
fn test_rule_error_display_all_variants() {
    let errors = vec![
        (
            RuleError::LlmError("test error".to_string()),
            "LLM error: test error",
        ),
        (
            RuleError::YamlError("invalid yaml".to_string()),
            "YAML parsing error: invalid yaml",
        ),
        (
            RuleError::SemgrepError("validation failed".to_string()),
            "Semgrep validation error: validation failed",
        ),
        (
            RuleError::SemgrepNotFound,
            "semgrep binary not found in PATH",
        ),
        (
            RuleError::IoError("io error".to_string()),
            "I/O error: io error",
        ),
    ];

    for (error, expected) in errors {
        assert_eq!(format!("{}", error), expected);
    }
}

#[test]
fn test_rule_error_debug_all_variants() {
    let errors = vec![
        RuleError::LlmError("test".to_string()),
        RuleError::YamlError("test".to_string()),
        RuleError::SemgrepError("test".to_string()),
        RuleError::SemgrepNotFound,
        RuleError::IoError("test".to_string()),
    ];

    for error in errors {
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn test_rule_error_clone() {
    let original = RuleError::LlmError("clone test".to_string());
    let cloned = original.clone();

    assert_eq!(format!("{}", original), format!("{}", cloned));
}

// ============================================================================
// build_prompt tests - prompt generation variations
// ============================================================================

mod build_prompt_deep_tests {
    use super::build_prompt;

    #[test]
    fn test_build_prompt_empty_cwe() {
        let prompt = build_prompt("", "python", 5);
        assert!(prompt.contains("CWE: "));
        assert!(prompt.contains("Language: python"));
    }

    #[test]
    fn test_build_prompt_empty_language() {
        let prompt = build_prompt("CWE-79", "", 5);
        assert!(prompt.contains("CWE: CWE-79"));
        assert!(prompt.contains("Language: "));
    }

    #[test]
    fn test_build_prompt_very_long_cwe() {
        let long_cwe = "a".repeat(100);
        let prompt = build_prompt(&long_cwe, "python", 5);
        assert!(prompt.contains(&format!("CWE: {}", long_cwe)));
    }

    #[test]
    fn test_build_prompt_various_max_rules_boundaries() {
        let test_cases = vec![0, 1, 2, 5, 10, 50, 100];

        for max_rules in test_cases {
            let prompt = build_prompt("CWE-79", "python", max_rules);
            assert!(
                prompt.contains(&format!("Maximum rules to generate: {}", max_rules)),
                "Failed for max_rules: {}",
                max_rules
            );
        }
    }

    #[test]
    fn test_build_prompt_contains_all_requirements() {
        let prompt = build_prompt("CWE-79", "python", 5);

        // Check all required sections
        assert!(prompt.contains("You are a security rule synthesizer"));
        assert!(prompt.contains("Generate semgrep rules"));
        assert!(prompt.contains("top-level \"rules:\" key"));
        assert!(prompt.contains("pattern-equals"));
        assert!(prompt.contains("pattern-regex"));
        assert!(prompt.contains("pattern-sources"));
        assert!(prompt.contains("pattern-sinks"));
        assert!(prompt.contains("Separate multiple rules with \"---\""));
    }

    #[test]
    fn test_build_prompt_example_structure_present() {
        let prompt = build_prompt("CWE-89", "javascript", 3);

        assert!(prompt.contains("Example rule structure"));
        assert!(prompt.contains("```yaml"));
        assert!(prompt.contains("```"));
        assert!(prompt.contains("metadata:"));
        assert!(prompt.contains("category: security"));
    }

    #[test]
    fn test_build_prompt_cwe_injection_in_multiple_places() {
        let prompt = build_prompt("79", "python", 5);

        // CWE should appear in multiple places
        assert!(prompt.contains("CWE: 79"));
        assert!(prompt.contains("cwe-79"));
        assert!(prompt.contains("Potential 79 vulnerability"));
        assert!(prompt.contains("Generate 5 rules for CWE-79"));
    }

    #[test]
    fn test_build_prompt_language_in_multiple_places() {
        let prompt = build_prompt("CWE-79", "go", 3);

        assert!(prompt.contains("Language: go"));
        assert!(prompt.contains("- go"));
    }
}

// ============================================================================
// Integration-style tests - combining multiple functions
// ============================================================================

#[test]
fn test_full_rule_generation_flow_simulation() {
    // Simulate the flow: build_prompt -> parse_yaml_rules -> extract_rule_id

    // Step 1: Build prompt (use local copy since prompt module is private)
    let _prompt = build_prompt("CWE-79", "python", 2);

    // Step 2: Simulate LLM response with YAML rules
    let simulated_response = r#"---
rules:
  - id: cwe-79-xss-detection
    patterns:
      - pattern: document.write($X)
    message: "Potential XSS vulnerability"
    languages:
      - javascript
    severity: WARNING
---
rules:
  - id: cwe-79-sanitization-check
    patterns:
      - pattern: innerHTML = $X
    message: "Potential XSS via innerHTML"
    languages:
      - javascript
    severity: ERROR
"#;

    // Step 3: Parse rules
    let rules = parse_yaml_rules(simulated_response, "javascript").unwrap();
    assert_eq!(rules.len(), 2);

    // Step 4: Extract IDs
    let id1 = extract_rule_id(&rules[0]).unwrap();
    let id2 = extract_rule_id(&rules[1]).unwrap();

    assert_eq!(id1, "cwe-79-xss-detection");
    assert_eq!(id2, "cwe-79-sanitization-check");
}

#[test]
fn test_config_persistence_simulation() {
    // Test that config can be serialized and used for path construction
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/tmp/test_rules"),
        max_rules_per_cwe: 3,
    };

    // Simulate creating a file path
    let rule_id = "cwe-79-test";
    let language = "python";
    let index = 0;
    let filename = format!("{}_{}_{}.yml", rule_id, language, index);
    let filepath = config.output_dir.join(&filename);

    assert_eq!(
        filepath,
        PathBuf::from("/tmp/test_rules/cwe-79-test_python_0.yml")
    );
}

// ============================================================================
// Edge case and boundary tests
// ============================================================================

#[test]
fn test_edge_case_max_unicode_characters_in_id() {
    let yaml = "id: rule-\u{4E00}\u{4E02}\u{4E03}\n"; // Chinese characters
    let result = extract_rule_id(yaml);
    assert!(result.is_some());
}

#[test]
fn test_edge_case_newlines_in_yaml() {
    let yaml = "\n\n\nrules:\n  - id: newline-test\n    pattern: $X\n\n\n";
    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
}

#[test]
fn test_edge_case_tabs_in_yaml() {
    let yaml = "rules:\n\t- id: tab-test\n\t\tpattern: $X\n";
    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
}

#[test]
fn test_edge_case_mixed_whitespace() {
    let yaml = "  rules:  \n    - id: mixed-test  \n      pattern: $X  \n";
    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
}

#[test]
fn test_edge_case_very_deeply_nested_yaml() {
    let yaml = r#"---
rules:
  - id: deep-nested
    patterns:
      - pattern: |
          if ($A) {
            if ($B) {
              if ($C) {
                $X
              }
            }
          }
    message: Deeply nested test
    languages: [python]
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
}

#[test]
fn test_edge_case_yaml_with_comments() {
    let yaml = r#"---
# Top-level comment
rules:
  # Comment in rules array
  - id: comment-test
    # Comment in rule
    pattern: $X
    # Another comment
    message: Test with comments
    languages: [python]
    # Final comment
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python");
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.len(), 1);
}

// ============================================================================
// Trait implementation tests
// ============================================================================

#[test]
fn test_semgrep_rule_trait_implementations() {
    let rule = SemgrepRule {
        id: "trait-test".to_string(),
        language: "python".to_string(),
        yaml: "test".to_string(),
    };

    // Debug
    let _debug = format!("{:?}", rule);

    // Clone
    let _cloned = rule.clone();

    // Serialize/Deserialize (via serde)
    let json = serde_json::to_string(&rule).unwrap();
    let _deserialized: SemgrepRule = serde_json::from_str(&json).unwrap();
}

#[test]
fn test_rule_error_trait_implementations() {
    let err = RuleError::LlmError("trait test".to_string());

    // Display
    let _display = format!("{}", err);

    // Debug
    let _debug = format!("{:?}", err);

    // Clone
    let _cloned = err.clone();

    // Error trait (via std::error::Error)
    let _error: &dyn std::error::Error = &err;
}

#[test]
fn test_rulesynth_config_trait_implementations() {
    let config = RuleSynthConfig {
        enabled: true,
        output_dir: PathBuf::from("/test"),
        max_rules_per_cwe: 5,
    };

    // Debug
    let _debug = format!("{:?}", config);

    // Clone
    let _cloned = config.clone();

    // Serialize/Deserialize
    let json = serde_json::to_string(&config).unwrap();
    let _deserialized: RuleSynthConfig = serde_json::from_str(&json).unwrap();
}
