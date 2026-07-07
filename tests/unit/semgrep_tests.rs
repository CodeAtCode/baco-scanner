//! Unit tests for semgrep module
//!
//! These tests cover JSON parsing, finding extraction, error handling,
//! and edge cases for the SemgrepRunner functionality.

use baco::findings::Severity;
use baco::semgrep::{extract_code_snippet, SemgrepRunner};
use std::fs::File;
use std::io::Write;
use tempfile::NamedTempFile;

// ============================================================================
// SemgrepRunner Construction Tests
// ============================================================================

#[test]
fn test_semgrep_runner_new_default() {
    let runner = SemgrepRunner::new(None, vec![]);
    assert!(runner.config_path.is_none());
    assert!(runner.exclude_rules.is_empty());
}

#[test]
fn test_semgrep_runner_new_with_config() {
    let config = "/path/to/config.yml".to_string();
    let runner = SemgrepRunner::new(Some(config.clone()), vec![]);
    assert_eq!(runner.config_path, Some(config));
}

#[test]
fn test_semgrep_runner_new_with_exclude_rules() {
    let rules = vec!["rule1".to_string(), "rule2".to_string()];
    let runner = SemgrepRunner::new(None, rules.clone());
    assert_eq!(runner.exclude_rules, rules);
}

#[test]
fn test_semgrep_runner_new_with_both_options() {
    let config = "/custom/config.yml".to_string();
    let rules = vec!["python.lang".to_string()];
    let runner = SemgrepRunner::new(Some(config.clone()), rules.clone());
    assert_eq!(runner.config_path, Some(config));
    assert_eq!(runner.exclude_rules, rules);
}

// ============================================================================
// Rule Exclusion Tests (should_exclude_rule)
// ============================================================================

#[test]
fn test_should_exclude_rule_empty_exclusions() {
    let runner = SemgrepRunner::new(None, vec![]);
    assert!(!runner.should_exclude_rule("any.rule"));
    assert!(!runner.should_exclude_rule("python.lang.security"));
}

#[test]
fn test_should_exclude_rule_exact_match() {
    let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
    assert!(runner.should_exclude_rule("python.lang.security"));
}

#[test]
fn test_should_exclude_rule_prefix_match() {
    let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
    assert!(runner.should_exclude_rule("python.lang.security"));
    assert!(runner.should_exclude_rule("python.lang.ast"));
    assert!(runner.should_exclude_rule("python.lang.security.audit"));
}

#[test]
fn test_should_exclude_rule_no_match_different_prefix() {
    let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
    assert!(!runner.should_exclude_rule("javascript.lang"));
    assert!(!runner.should_exclude_rule("rust.lang"));
}

#[test]
fn test_should_exclude_rule_multiple_patterns() {
    let runner = SemgrepRunner::new(
        None,
        vec![
            "python.lang".to_string(),
            "javascript.security".to_string(),
        ],
    );
    assert!(runner.should_exclude_rule("python.lang.security"));
    assert!(runner.should_exclude_rule("javascript.security.xss"));
    assert!(!runner.should_exclude_rule("rust.security"));
}

#[test]
fn test_should_exclude_rule_case_sensitive() {
    let runner = SemgrepRunner::new(None, vec!["Python.Lang".to_string()]);
    // Should be case-sensitive - lowercase should not match
    assert!(!runner.should_exclude_rule("python.lang"));
    assert!(runner.should_exclude_rule("Python.Lang"));
}

#[test]
fn test_should_exclude_rule_partial_prefix_no_match() {
    let runner = SemgrepRunner::new(None, vec!["python".to_string()]);
    assert!(runner.should_exclude_rule("python.lang"));
    assert!(runner.should_exclude_rule("python.security"));
    assert!(!runner.should_exclude_rule("javascript"));
}

#[test]
fn test_should_exclude_rule_nested_prefix() {
    let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
    assert!(runner.should_exclude_rule("python.lang.security"));
    assert!(runner.should_exclude_rule("python.lang.security.audit"));
    assert!(runner.should_exclude_rule("python.lang.security.audit.dangerous"));
    assert!(!runner.should_exclude_rule("python.lang.ast"));
}

// ============================================================================
// JSON Parsing - Basic Tests
// ============================================================================

#[test]
fn test_parse_json_empty_results_array() {
    let mock_json = r#"{"results": []}"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_missing_results_key() {
    let mock_json = r#"{"data": [], "errors": []}"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_invalid_json() {
    let mock_json = r#"not valid json"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let result = runner.parse_json_output(mock_json.as_bytes());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse"));
}

#[test]
fn test_parse_json_empty_bytes() {
    let runner = SemgrepRunner::new(None, vec![]);
    let result = runner.parse_json_output(b"");
    assert!(result.is_err());
}

#[test]
fn test_parse_json_null_results() {
    let mock_json = r#"{"results": null}"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

// ============================================================================
// JSON Parsing - Finding Extraction Tests
// ============================================================================

#[test]
fn test_parse_json_single_finding() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.injection",
                "path": "vulnerable.py",
                "start": {"line": 42, "col": 10},
                "extra": {
                    "message": "SQL injection detected",
                    "metadata": {"cwe": ["CWE-89"]}
                }
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "python.security.injection");
    assert_eq!(findings[0].file_path, "vulnerable.py");
    assert_eq!(findings[0].line_number, Some(42));
    assert_eq!(findings[0].cwe_id, Some("CWE-89".to_string()));
    assert_eq!(findings[0].description, "SQL injection detected");
}

#[test]
fn test_parse_json_multiple_unique_findings() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "rule.one",
                "path": "file1.py",
                "start": {"line": 1},
                "extra": {"message": "Issue 1", "metadata": {"cwe": ["CWE-1"]}}
            },
            {
                "check_id": "rule.two",
                "path": "file2.py",
                "start": {"line": 2},
                "extra": {"message": "Issue 2", "metadata": {"cwe": ["CWE-2"]}}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 2);
}

#[test]
fn test_parse_json_aggregated_findings() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "multi.location",
                "path": "file1.py",
                "start": {"line": 1},
                "extra": {"message": "Same issue", "metadata": {"cwe": ["CWE-1"]}}
            },
            {
                "check_id": "multi.location",
                "path": "file2.py",
                "start": {"line": 5},
                "extra": {"message": "Same issue", "metadata": {"cwe": ["CWE-1"]}}
            },
            {
                "check_id": "multi.location",
                "path": "file3.py",
                "start": {"line": 10},
                "extra": {"message": "Same issue", "metadata": {"cwe": ["CWE-1"]}}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // All findings with same check_id should be aggregated into one
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "multiple_files");
    assert!(findings[0].code_snippet.as_ref().unwrap().contains("3 locations"));
}

// ============================================================================
// JSON Parsing - Severity Detection Tests
// ============================================================================

#[test]
fn test_parse_json_severity_critical() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "critical.vulnerability",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Critical issue"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_parse_json_severity_high() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "high.risk.issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "High risk"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_parse_json_severity_medium() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "medium.severity.issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Medium"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].severity, Severity::Medium);
}

#[test]
fn test_parse_json_severity_low() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "low.priority.issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Low"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].severity, Severity::Low);
}

#[test]
fn test_parse_json_severity_info_default() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "unknown.severity",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Info"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn test_parse_json_severity_case_insensitive() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "CRITICAL.issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].severity, Severity::Critical);
}

// ============================================================================
// JSON Parsing - Missing Fields Tests
// ============================================================================

#[test]
fn test_parse_json_missing_check_id() {
    let mock_json = r#"{
        "results": [
            {
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "No check_id"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_missing_path() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "start": {"line": 1},
                "extra": {"message": "No path"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_missing_start_line() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "extra": {"message": "No line"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_missing_extra_field() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
    assert_eq!(findings[0].cwe_id, None);
}

#[test]
fn test_parse_json_missing_message() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"metadata": {"cwe": ["CWE-1"]}}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    // Should use fallback description with check_id
    assert!(findings[0].description.contains("test.rule"));
}

#[test]
fn test_parse_json_missing_cwe() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "No CWE"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].cwe_id, None);
}

#[test]
fn test_parse_json_empty_cwe_array() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Empty CWE", "metadata": {"cwe": []}}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].cwe_id, None);
}

// ============================================================================
// JSON Parsing - Rule Exclusion Tests
// ============================================================================

#[test]
fn test_parse_json_excludes_matching_rule() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.lang.security",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Should be excluded"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_excludes_nested_rule() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Should be excluded"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_includes_non_matching_rule() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "javascript.security.xss",
                "path": "test.js",
                "start": {"line": 1},
                "extra": {"message": "Should be included"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "test.js");
}

#[test]
fn test_parse_json_multiple_rules_with_exclusions() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.lang.security",
                "path": "test1.py",
                "start": {"line": 1},
                "extra": {"message": "Excluded"}
            },
            {
                "check_id": "javascript.xss",
                "path": "test2.js",
                "start": {"line": 2},
                "extra": {"message": "Included"}
            },
            {
                "check_id": "python.lang.ast",
                "path": "test3.py",
                "start": {"line": 3},
                "extra": {"message": "Excluded"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "test2.js");
}

// ============================================================================
// Code Snippet Extraction Tests
// ============================================================================

#[test]
fn test_extract_code_snippet_file_not_found() {
    let snippet = extract_code_snippet("/nonexistent/path/file.rs", 42, 2);
    assert!(snippet.contains("file not found"));
    assert!(snippet.contains("Line 42"));
}

#[test]
fn test_extract_code_snippet_with_context() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let content = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\n";
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let snippet = extract_code_snippet(temp_file.path().to_str().unwrap(), 4, 1);

    assert!(snippet.contains("line 3"));
    assert!(snippet.contains(">>")); // Marker for target line
    assert!(snippet.contains("line 4"));
    assert!(snippet.contains("line 5"));

    // Clean up
    drop(temp_file);
}

#[test]
fn test_extract_code_snippet_target_first_line() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let content = "first\nsecond\nthird\n";
    temp_file.write_all(content.as_bytes()).unwrap();

    let snippet = extract_code_snippet(temp_file.path().to_str().unwrap(), 1, 2);

    assert!(snippet.contains("first"));
    assert!(snippet.contains(">>"));
    assert!(snippet.contains("second"));

    drop(temp_file);
}

#[test]
fn test_extract_code_snippet_target_last_line() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let content = "first\nsecond\nthird\n";
    temp_file.write_all(content.as_bytes()).unwrap();

    let snippet = extract_code_snippet(temp_file.path().to_str().unwrap(), 3, 1);

    assert!(snippet.contains("second"));
    assert!(snippet.contains(">>"));
    assert!(snippet.contains("third"));

    drop(temp_file);
}

#[test]
fn test_extract_code_snippet_target_beyond_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let content = "line 1\nline 2\n";
    temp_file.write_all(content.as_bytes()).unwrap();

    let snippet = extract_code_snippet(temp_file.path().to_str().unwrap(), 100, 2);

    // Should show last available lines
    assert!(snippet.contains("line 2"));

    drop(temp_file);
}

#[test]
fn test_extract_code_snippet_target_line_zero() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let content = "line 1\nline 2\n";
    temp_file.write_all(content.as_bytes()).unwrap();

    let snippet = extract_code_snippet(temp_file.path().to_str().unwrap(), 0, 1);

    // Should handle gracefully (saturating_sub handles 0)
    assert!(snippet.contains("line"));

    drop(temp_file);
}

#[test]
fn test_extract_code_snippet_large_context() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let content = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
    temp_file.write_all(content.as_bytes()).unwrap();

    let snippet = extract_code_snippet(temp_file.path().to_str().unwrap(), 5, 10);

    // Should show all lines since context is larger than file
    assert!(snippet.contains("1"));
    assert!(snippet.contains("5"));
    assert!(snippet.contains("10"));

    drop(temp_file);
}

#[test]
fn test_extract_code_snippet_empty_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    // Empty file
    temp_file.flush().unwrap();

    let snippet = extract_code_snippet(temp_file.path().to_str().unwrap(), 1, 2);

    assert!(snippet.is_empty() || !snippet.contains(">>"));

    drop(temp_file);
}

#[test]
fn test_extract_code_snippet_single_line_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let content = "single line\n";
    temp_file.write_all(content.as_bytes()).unwrap();

    let snippet = extract_code_snippet(temp_file.path().to_str().unwrap(), 1, 5);

    assert!(snippet.contains("single line"));
    assert!(snippet.contains(">>"));

    drop(temp_file);
}

// ============================================================================
// Confidence Score Tests
// ============================================================================

#[test]
fn test_parse_json_confidence_score() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    // Semgrep findings have fixed confidence score of 0.7
    assert_eq!(findings[0].confidence_score, 0.7);
}

// ============================================================================
// Sources Field Tests
// ============================================================================

#[test]
fn test_parse_json_sources_field() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].sources, vec!["semgrep".to_string()]);
}

// ============================================================================
// Recommendation Field Tests
// ============================================================================

#[test]
fn test_parse_json_recommendation_field() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(
        findings[0].recommendation,
        Some("Review and fix this issue".to_string())
    );
}

// ============================================================================
// Code Location Tests
// ============================================================================

#[test]
fn test_parse_json_code_location_single() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].code_location, Some("test.py:42".to_string()));
}

#[test]
fn test_parse_json_code_location_aggregated() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "multi.rule",
                "path": "file1.py",
                "start": {"line": 1},
                "extra": {"message": "Test"}
            },
            {
                "check_id": "multi.rule",
                "path": "file2.py",
                "start": {"line": 2},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    // Aggregated findings have no single code location
    assert!(findings[0].code_location.is_none());
}

// ============================================================================
// LL Model Field Tests
// ============================================================================

#[test]
fn test_parse_json_llm_model_field() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].llm_model, Some("semgrep".to_string()));
}

// ============================================================================
// Edge Cases - Malformed JSON
// ============================================================================

#[test]
fn test_parse_json_malformed_nested_structure() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": "not_an_object"
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    // Missing valid start.line should skip this finding
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_null_start_object() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": null
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_extra_as_string() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": "not_an_object"
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    // Should handle gracefully, missing extra fields
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
}

// ============================================================================
// Edge Cases - Special Characters
// ============================================================================

#[test]
fn test_parse_json_unicode_in_message() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Unicode: \u{4e2d\u{6587} \u{65e5\u{7528}"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let result = runner.parse_json_output(mock_json.as_bytes());
    assert!(result.is_ok());
}

#[test]
fn test_parse_json_special_chars_in_path() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "path/with spaces/file.py",
                "start": {"line": 1},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].file_path, "path/with spaces/file.py");
}

// ============================================================================
// Edge Cases - Line Number Edge Values
// ============================================================================

#[test]
fn test_parse_json_line_number_zero() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 0},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].line_number, Some(0));
}

#[test]
fn test_parse_json_large_line_number() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 999999},
                "extra": {"message": "Test"}
            }
        ]
    }"#;
    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
    assert_eq!(findings[0].line_number, Some(999999));
}

// ============================================================================
// Integration-style Tests
// ============================================================================

#[test]
fn test_full_pipeline_single_finding() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.lang.security.injection.sql",
                "path": "app/models/user.py",
                "start": {"line": 42, "col": 15},
                "extra": {
                    "message": "SQL injection vulnerability detected",
                    "metadata": {"cwe": ["CWE-89", "CWE-20"]}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(
        Some("/config/semgrep.yml".to_string()),
        vec!["python.lang.ast".to_string()],
    );

    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "python.lang.security.injection.sql");
    assert_eq!(findings[0].file_path, "app/models/user.py");
    assert_eq!(findings[0].line_number, Some(42));
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].cwe_id.is_some());
    assert!(findings[0].code_snippet.is_some());
    assert_eq!(findings[0].confidence_score, 0.7);
}

#[test]
fn test_full_pipeline_mixed_severities() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "critical.security.flaw",
                "path": "a.py",
                "start": {"line": 1},
                "extra": {"message": "Critical"}
            },
            {
                "check_id": "high.risk.issue",
                "path": "b.py",
                "start": {"line": 2},
                "extra": {"message": "High"}
            },
            {
                "check_id": "medium.warning",
                "path": "c.py",
                "start": {"line": 3},
                "extra": {"message": "Medium"}
            },
            {
                "check_id": "low.info",
                "path": "d.py",
                "start": {"line": 4},
                "extra": {"message": "Low"}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 4);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[1].severity, Severity::High);
    assert_eq!(findings[2].severity, Severity::Medium);
    assert_eq!(findings[3].severity, Severity::Low);
}

#[test]
fn test_full_pipeline_with_exclusions_and_aggregation() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.lang.security",
                "path": "excluded1.py",
                "start": {"line": 1},
                "extra": {"message": "Excluded"}
            },
            {
                "check_id": "multi.issue",
                "path": "file1.py",
                "start": {"line": 1},
                "extra": {"message": "Aggregated"}
            },
            {
                "check_id": "multi.issue",
                "path": "file2.py",
                "start": {"line": 2},
                "extra": {"message": "Aggregated"}
            },
            {
                "check_id": "unique.issue",
                "path": "unique.py",
                "start": {"line": 3},
                "extra": {"message": "Unique"}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // Should have 2 findings: 1 aggregated + 1 unique
    assert_eq!(findings.len(), 2);

    // Find which is which
    let aggregated = findings.iter().find(|f| f.file_path == "multiple_files").unwrap();
    let unique = findings.iter().find(|f| f.file_path == "unique.py").unwrap();

    assert_eq!(aggregated.title, "multi.issue");
    assert_eq!(unique.title, "unique.issue");
}

#[test]
fn test_parse_severity_matching() {
    // Test all severity levels based on check_id
    let test_cases = vec![
        ("critical.vulnerability", baco::scanner_types::Severity::Critical),
        ("HIGH.error", baco::scanner_types::Severity::High),
        ("medium.warning", baco::scanner_types::Severity::Medium),
        ("low.issue", baco::scanner_types::Severity::Low),
        ("info.notice", baco::scanner_types::Severity::Info),
        ("unknown.type", baco::scanner_types::Severity::Info),
    ];

    for (check_id, expected_severity) in test_cases {
        let mock_json = format!(r#"{{
            "results": [
                {{
                    "check_id": "{}",
                    "path": "test.py",
                    "start": {{"line": 1}},
                    "extra": {{"message": "Test"}}
                }}
            ]
        }}"#, check_id);

        let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

        assert_eq!(findings.len(), 1, "Failed for check_id: {}", check_id);
        assert_eq!(findings[0].severity, expected_severity, "Severity mismatch for: {}", check_id);
    }
}

#[test]
fn test_parse_cwe_id_extraction() {
    // Test with CWE metadata present
    let mock_json_with_cwe = r#"{
        "results": [
            {
                "check_id": "test.issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Test finding",
                    "metadata": {
                        "cwe": ["CWE-79", "CWE-80"]
                    }
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
    let findings = runner.parse_json_output(mock_json_with_cwe.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].cwe_id.is_some());
    assert_eq!(findings[0].cwe_id.as_ref().unwrap(), "CWE-79");
}

#[test]
fn test_parse_without_cwe_id() {
    // Test without CWE metadata
    let mock_json_no_cwe = r#"{
        "results": [
            {
                "check_id": "test.issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Test finding"
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(None, vec!["python.lang".to_string()]);
    let findings = runner.parse_json_output(mock_json_no_cwe.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].cwe_id.is_none());
}

#[test]
fn test_semgrep_severity_mapping_edge_cases() {
    let mock_json = r#"{
        "results": [
            {"check_id": "security.critical.auth", "path": "test.py", "line": 10, "extra": {"message": "critical", "severity": "critical"}},
            {"check_id": "security.high.sql", "path": "test.py", "line": 20, "extra": {"message": "high", "severity": "high"}},
            {"check_id": "security.medium.xss", "path": "test.py", "line": 30, "extra": {"message": "medium", "severity": "medium"}},
            {"check_id": "security.low.info", "path": "test.py", "line": 40, "extra": {"message": "low", "severity": "low"}},
            {"check_id": "unknown.rule", "path": "test.py", "line": 50, "extra": {"message": "unknown", "severity": "info"}}
        ]
    }"#;

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 5);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[1].severity, Severity::High);
    assert_eq!(findings[2].severity, Severity::Medium);
    assert_eq!(findings[3].severity, Severity::Low);
    assert_eq!(findings[4].severity, Severity::Info);
}
