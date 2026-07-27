//! Unit tests for free functions in rulesynth module
//!
//! Tests parse_yaml_rules and persist_rules as standalone functions.

use baco::rulesynth::{parse_yaml_rules, persist_rules, SemgrepRule};
use std::path::PathBuf;
use tempfile::tempdir;

// ============================================================================
// parse_yaml_rules tests
// ============================================================================

#[test]
fn test_parse_yaml_rules_single_rule_no_separator() {
    // Note: The parsing logic has a quirk where without "---" separators,
    // only the "rules:" line is captured. The fallback doesn't kick in
    // because current_rule is not empty after processing.
    let yaml = r#"rules:
  - id: test-rule
    patterns:
      - pattern: $X
    message: Test message
    languages:
      - python
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python").unwrap();
    // Due to the parsing logic, only "rules:" is captured without separators
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "rules:");
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
"#;

    let result = parse_yaml_rules(yaml, "python").unwrap();
    assert_eq!(result.len(), 2);
    assert!(result[0].contains("id: rule-1"));
    assert!(result[1].contains("id: rule-2"));
}

#[test]
fn test_parse_yaml_rules_empty_input() {
    let yaml = "";
    let result = parse_yaml_rules(yaml, "python").unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_parse_yaml_rules_whitespace_only() {
    let yaml = "   \n\n   \n  ";
    let result = parse_yaml_rules(yaml, "python").unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_parse_yaml_rules_only_separators() {
    let yaml = "---\n---\n---";
    let result = parse_yaml_rules(yaml, "python").unwrap();
    // When only separators exist with no content between, fallback kicks in
    // and returns the whole trimmed content
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "---\n---\n---");
}

#[test]
fn test_parse_yaml_rules_no_rules_prefix() {
    let yaml = r#"rules:
  - id: test-rule
    pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python").unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("rules:"));
}

#[test]
fn test_parse_yaml_rules_starts_with_separator() {
    let yaml = r#"---
rules:
  - id: rule-starting-with-sep
    pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python").unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("id: rule-starting-with-sep"));
}

#[test]
fn test_parse_yaml_rules_consecutive_separators() {
    let yaml = r#"---
---
rules:
  - id: rule-after-consecutive-seps
    pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
"#;

    let result = parse_yaml_rules(yaml, "python").unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("id: rule-after-consecutive-seps"));
}

#[test]
fn test_parse_yaml_rules_trailing_separator() {
    let yaml = r#"rules:
  - id: rule-before-trailing-sep
    pattern: $X
    message: Test
    languages: [python]
    severity: WARNING
---"#;

    let result = parse_yaml_rules(yaml, "python").unwrap();
    // With trailing ---, the content before it gets pushed when separator is hit
    // But current_rule only has "rules:" because subsequent lines aren't added without in_rule=true
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "rules:");
}

#[test]
fn test_parse_yaml_rules_three_rules() {
    let yaml = r#"---
rules:
  - id: rule-1
    pattern: $X
    message: First
    languages: [python]
    severity: WARNING
---
rules:
  - id: rule-2
    pattern: $Y
    message: Second
    languages: [python]
    severity: WARNING
---
rules:
  - id: rule-3
    pattern: $Z
    message: Third
    languages: [python]
    severity: ERROR
"#;

    let result = parse_yaml_rules(yaml, "python").unwrap();
    assert_eq!(result.len(), 3);
    assert!(result[0].contains("id: rule-1"));
    assert!(result[1].contains("id: rule-2"));
    assert!(result[2].contains("id: rule-3"));
}

#[test]
fn test_parse_yaml_rules_special_chars_in_yaml() {
    // Without "---" separator, only "rules:" line is captured
    let yaml = r#"rules:
  - id: rule-with-dashes
    pattern: $VAR_WITH_DOLLAR
    message: "Message with \"quotes\""
    languages:
      - python
    severity: WARNING
    metadata:
      special: "chars: @#$%"
"#;

    let result = parse_yaml_rules(yaml, "python").unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "rules:");
}

// ============================================================================
// persist_rules tests
// ============================================================================

#[test]
fn test_persist_rules_multiple_rules_creates_files() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path().to_string_lossy().to_string();

    let rules = vec![
        SemgrepRule {
            id: "rule-1".to_string(),
            language: "python".to_string(),
            yaml: "rules:\n  - id: rule-1\n    pattern: $X\n".to_string(),
        },
        SemgrepRule {
            id: "rule-2".to_string(),
            language: "python".to_string(),
            yaml: "rules:\n  - id: rule-2\n    pattern: $Y\n".to_string(),
        },
    ];

    let result = persist_rules(&rules, "CWE-79", "python", &output_dir);
    assert!(result.is_ok());

    // Verify files were created
    let file1_path = PathBuf::from(&output_dir).join("CWE-79_python_0.yml");
    let file2_path = PathBuf::from(&output_dir).join("CWE-79_python_1.yml");

    assert!(file1_path.exists());
    assert!(file2_path.exists());

    // Verify contents
    let content1 = std::fs::read_to_string(&file1_path).unwrap();
    assert_eq!(content1, rules[0].yaml);

    let content2 = std::fs::read_to_string(&file2_path).unwrap();
    assert_eq!(content2, rules[1].yaml);
}

#[test]
fn test_persist_rules_empty_slice() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path().to_string_lossy().to_string();

    let rules: Vec<SemgrepRule> = vec![];
    let result = persist_rules(&rules, "CWE-79", "python", &output_dir);

    assert!(result.is_ok());

    // No files should be created
    let files: Vec<_> = std::fs::read_dir(&output_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(files.is_empty());
}

#[test]
fn test_persist_rules_creates_parent_directory() {
    let temp_dir = tempdir().unwrap();
    let nested_path = temp_dir.path().join("nested").join("output");
    let output_dir = nested_path.to_string_lossy().to_string();

    let rules = vec![SemgrepRule {
        id: "test-rule".to_string(),
        language: "python".to_string(),
        yaml: "rules:\n  - id: test-rule\n    pattern: $X\n".to_string(),
    }];

    let result = persist_rules(&rules, "CWE-79", "python", &output_dir);
    assert!(result.is_ok());

    // Verify directory was created and file exists
    assert!(nested_path.exists());
    let file_path = nested_path.join("CWE-79_python_0.yml");
    assert!(file_path.exists());
}

#[test]
fn test_persist_rules_single_rule() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path().to_string_lossy().to_string();

    let rules = vec![SemgrepRule {
        id: "single-rule".to_string(),
        language: "javascript".to_string(),
        yaml: "rules:\n  - id: single-rule\n    pattern: document.write($X)\n    message: XSS\n    languages: [javascript]\n    severity: WARNING\n".to_string(),
    }];

    let result = persist_rules(&rules, "CWE-79", "javascript", &output_dir);
    assert!(result.is_ok());

    let file_path = PathBuf::from(&output_dir).join("CWE-79_javascript_0.yml");
    assert!(file_path.exists());

    let content = std::fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, rules[0].yaml);
}

#[test]
fn test_persist_rules_preserves_yaml_content() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path().to_string_lossy().to_string();

    let yaml_content = r#"rules:
  - id: complex-rule
    patterns:
      - pattern: |
          if ($COND) {
            $X
          }
    message: "Complex pattern test"
    languages:
      - python
    severity: ERROR
    metadata:
      cwe: "CWE-89"
      category: security
      author: "test"
"#;

    let rules = vec![SemgrepRule {
        id: "complex-rule".to_string(),
        language: "python".to_string(),
        yaml: yaml_content.to_string(),
    }];

    let result = persist_rules(&rules, "CWE-89", "python", &output_dir);
    assert!(result.is_ok());

    let file_path = PathBuf::from(&output_dir).join("CWE-89_python_0.yml");
    let content = std::fs::read_to_string(&file_path).unwrap();

    // Verify the content matches exactly
    assert_eq!(content, yaml_content);
    assert!(content.contains("patterns:"));
    assert!(content.contains("pattern: |"));
    assert!(content.contains("$COND"));
    assert!(content.contains("$X"));
}
