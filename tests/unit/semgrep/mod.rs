//! Unit tests for SemgrepRunner and related functionality
//!
//! Covers:
//! - Settings parsing and configuration
//! - Semgrep execution (mocked)
//! - Rule matching and exclusion logic
//! - Result parsing and aggregation
//! - Edge cases: missing config, invalid rules, empty results

use baco::findings::Severity;
use baco::semgrep::SemgrepRunner;
use std::fs;

// Include edge case tests
mod parsing_edge_cases_tests;

// Include migrated inline tests
mod core_tests;

// ============================================================================
// SemgrepRunner Construction Tests
// ============================================================================

#[test]
fn test_semgrep_runner_default_construction() {
    let runner = SemgrepRunner::new(vec![], vec![]);

    assert!(runner.rulesets.is_empty());
    assert!(runner.exclude_rules.is_empty());
}

#[test]
fn test_semgrep_runner_with_config_path() {
    let config_path = "/path/to/.semgrep.yml".to_string();
    let runner = SemgrepRunner::new(vec![config_path.clone()], vec![]);

    assert_eq!(runner.rulesets, vec![config_path]);
    assert!(runner.exclude_rules.is_empty());
}

#[test]
fn test_semgrep_runner_with_exclude_rules() {
    let exclude_rules = vec![
        "python.lang.security".to_string(),
        "javascript.security.xss".to_string(),
    ];
    let runner = SemgrepRunner::new(vec![], exclude_rules.clone());

    assert!(runner.rulesets.is_empty());
    assert_eq!(runner.exclude_rules.len(), 2);
    assert!(runner
        .exclude_rules
        .contains(&"python.lang.security".to_string()));
    assert!(runner
        .exclude_rules
        .contains(&"javascript.security.xss".to_string()));
}

#[test]
fn test_semgrep_runner_with_both_config_and_excludes() {
    let config_path = "/custom/config.yml".to_string();
    let exclude_rules = vec!["rust.security".to_string()];
    let runner = SemgrepRunner::new(vec![config_path.clone()], exclude_rules.clone());

    assert_eq!(runner.rulesets, vec![config_path]);
    assert_eq!(runner.exclude_rules.len(), 1);
}

// ============================================================================
// Rule Exclusion Logic Tests
// ============================================================================

#[test]
fn test_should_exclude_single_exact_match() {
    let runner = SemgrepRunner::new(vec![], vec!["exact.rule".to_string()]);

    assert!(runner.should_exclude_rule("exact.rule"));
    assert!(runner.should_exclude_rule("exact.rule.sub")); // Prefix match
    assert!(!runner.should_exclude_rule("other.rule"));
}

#[test]
fn test_should_exclude_prefix_matches_all_subrules() {
    let runner = SemgrepRunner::new(vec![], vec!["python.lang".to_string()]);

    // Prefix should match all sub-rules
    assert!(runner.should_exclude_rule("python.lang.security"));
    assert!(runner.should_exclude_rule("python.lang.ast"));
    assert!(runner.should_exclude_rule("python.lang.security.audit"));
    assert!(runner.should_exclude_rule("python.lang.insecure"));
}

#[test]
fn test_should_exclude_case_sensitive() {
    let runner = SemgrepRunner::new(vec![], vec!["Python.Security".to_string()]);

    // Should be case-sensitive - exact match only
    assert!(runner.should_exclude_rule("Python.Security"));
    assert!(!runner.should_exclude_rule("python.security"));
    assert!(!runner.should_exclude_rule("PYTHON.SECURITY"));
}

#[test]
fn test_should_exclude_with_multiple_overlapping_patterns() {
    let runner = SemgrepRunner::new(
        vec![],
        vec![
            "python".to_string(),
            "javascript.security".to_string(),
            "rust.memory".to_string(),
        ],
    );

    // Should match any pattern
    assert!(runner.should_exclude_rule("python.anything"));
    assert!(runner.should_exclude_rule("javascript.security.xss"));
    assert!(runner.should_exclude_rule("rust.memory.safety"));
    assert!(!runner.should_exclude_rule("go.concurrency"));
}

#[test]
fn test_should_exclude_empty_pattern_list() {
    let runner = SemgrepRunner::new(vec![], vec![]);

    // No patterns means nothing excluded
    assert!(!runner.should_exclude_rule("any.rule"));
    assert!(!runner.should_exclude_rule("python.lang.security"));
}

#[test]
fn test_should_exclude_empty_rule_id() {
    let runner = SemgrepRunner::new(vec![], vec!["".to_string()]);

    // Empty pattern should match empty rule_id
    assert!(runner.should_exclude_rule(""));
    assert!(runner.should_exclude_rule("some.rule")); // Empty pattern matches all
}

#[test]
fn test_should_exclude_partial_prefix_no_match() {
    let runner = SemgrepRunner::new(vec![], vec!["python.lang".to_string()]);

    // Should not match similar but different prefixes
    assert!(!runner.should_exclude_rule("python-language"));
    assert!(!runner.should_exclude_rule("pythonlang"));
    assert!(!runner.should_exclude_rule("rust.lang"));
}

// ============================================================================
// JSON Parsing Tests - Basic
// ============================================================================

#[test]
fn test_parse_json_valid_single_finding() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.high-injection",
                "path": "vulnerable.py",
                "start": {"line": 42, "col": 5},
                "extra": {
                    "message": "SQL injection detected",
                    "metadata": {"cwe": ["CWE-89"]},
                    "severity": "HIGH"
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "python.security.high-injection");
    assert_eq!(findings[0].file_path, "vulnerable.py");
    assert_eq!(findings[0].line_number, Some(42));
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].cwe_id, Some("CWE-89".to_string()));
}

#[test]
fn test_parse_json_empty_results_array() {
    let mock_json = r#"{"results": []}"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_missing_results_key() {
    let mock_json = r#"{"data": [], "metadata": {}}"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // Missing results key should return empty, not error
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_invalid_json_format() {
    let invalid_json = r#"not valid json {"broken": "#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let result = runner.parse_json_output(invalid_json.as_bytes());

    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("Failed to parse semgrep JSON"));
}

#[test]
fn test_parse_json_not_array_root() {
    let not_array = r#""just a string""#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let result = runner.parse_json_output(not_array.as_bytes());

    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

// ============================================================================
// JSON Parsing Tests - Edge Cases
// ============================================================================

#[test]
fn test_parse_json_missing_start_line_skips_result() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "extra": {"message": "No line"}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // Missing start.line should skip the result
    assert!(findings.is_empty());
}

#[test]
fn test_parse_json_missing_extra_field_uses_defaults() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 5}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info); // Default severity
    assert!(findings[0].cwe_id.is_none());
    assert!(findings[0].description.contains("test.rule"));
}

#[test]
fn test_parse_json_null_fields_handled_gracefully() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": null,
                "path": null,
                "start": null,
                "extra": null
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // Null fields should be skipped
    assert!(findings.is_empty());
}

// ============================================================================
// JSON Parsing Tests - Severity Mapping
// ============================================================================

#[test]
fn test_severity_mapping_critical() {
    let mock_json = r#"{
        "results": [
            {"check_id": "critical.vulnerability", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_severity_mapping_high() {
    let mock_json = r#"{
        "results": [
            {"check_id": "high.risk.issue", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_severity_mapping_medium() {
    let mock_json = r#"{
        "results": [
            {"check_id": "medium.warning", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings[0].severity, Severity::Medium);
}

#[test]
fn test_severity_mapping_low() {
    let mock_json = r#"{
        "results": [
            {"check_id": "low.priority.note", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings[0].severity, Severity::Low);
}

#[test]
fn test_severity_mapping_unknown_defaults_to_info() {
    let mock_json = r#"{
        "results": [
            {"check_id": "unknown.category", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn test_severity_mapping_case_insensitive() {
    let mock_json = r#"{
        "results": [
            {"check_id": "CRITICAL.issue", "path": "test1.py", "start": {"line": 1}, "extra": {"metadata": {}}},
            {"check_id": "High.Risk", "path": "test2.py", "start": {"line": 2}, "extra": {"metadata": {}}},
            {"check_id": "MEDIUM.warning", "path": "test3.py", "start": {"line": 3}, "extra": {"metadata": {}}},
            {"check_id": "low.priority", "path": "test4.py", "start": {"line": 4}, "extra": {"metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // Sort by file path for deterministic ordering
    let mut sorted = findings.clone();
    sorted.sort_by(|a, b| a.file_path.cmp(&b.file_path));

    assert_eq!(sorted[0].severity, Severity::Critical); // test1.py
    assert_eq!(sorted[1].severity, Severity::High); // test2.py
    assert_eq!(sorted[2].severity, Severity::Medium); // test3.py
    assert_eq!(sorted[3].severity, Severity::Low); // test4.py
}

// ============================================================================
// Rule Exclusion in Parsing Tests
// ============================================================================

#[test]
fn test_parse_json_excludes_matched_rules() {
    let mock_json = r#"{
        "results": [
            {"check_id": "python.security.injection", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {}}},
            {"check_id": "python.lang.ast", "path": "test.py", "start": {"line": 2}, "extra": {"metadata": {}}},
            {"check_id": "javascript.security.xss", "path": "test.js", "start": {"line": 1}, "extra": {"metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec!["python.lang".to_string()]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // python.lang.ast should be excluded (prefix match)
    // python.security.injection and javascript.security.xss should remain
    assert_eq!(findings.len(), 2);
}

#[test]
fn test_parse_json_all_results_excluded() {
    let mock_json = r#"{
        "results": [
            {"check_id": "python.anything", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {}}},
            {"check_id": "python.else", "path": "test.py", "start": {"line": 2}, "extra": {"metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec!["python".to_string()]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // All results should be excluded
    assert!(findings.is_empty());
}

// ============================================================================
// Result Aggregation Tests
// ============================================================================

#[test]
fn test_aggregation_single_location_preserves_details() {
    let mock_json = r#"{
        "results": [
            {"check_id": "single.issue", "path": "unique.py", "start": {"line": 10}, "extra": {"message": "Single issue", "metadata": {"cwe": ["CWE-79"]}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "unique.py");
    assert_eq!(findings[0].line_number, Some(10));
    assert!(findings[0].code_snippet.is_some());
    assert_eq!(findings[0].cwe_id, Some("CWE-79".to_string()));
}

#[test]
fn test_aggregation_multiple_same_rule_creates_single_finding() {
    let mock_json = r#"{
        "results": [
            {"check_id": "multi.location", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Issue", "metadata": {}}},
            {"check_id": "multi.location", "path": "file2.py", "start": {"line": 5}, "extra": {"message": "Issue", "metadata": {}}},
            {"check_id": "multi.location", "path": "file3.py", "start": {"line": 10}, "extra": {"message": "Issue", "metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // Multiple same check_id should aggregate to single finding
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "multiple_files");
    assert!(findings[0].line_number.is_none());
    assert!(findings[0]
        .code_snippet
        .as_ref()
        .unwrap()
        .contains("Found in"));
}

#[test]
fn test_aggregation_different_rules_separate_findings() {
    let mock_json = r#"{
        "results": [
            {"check_id": "rule.one", "path": "test.py", "start": {"line": 1}, "extra": {"message": "One", "metadata": {}}},
            {"check_id": "rule.two", "path": "test.py", "start": {"line": 2}, "extra": {"message": "Two", "metadata": {}}},
            {"check_id": "rule.three", "path": "test.py", "start": {"line": 3}, "extra": {"message": "Three", "metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // Different check_ids should create separate findings
    assert_eq!(findings.len(), 3);
}

// ============================================================================
// Code Snippet in Findings Tests
// ============================================================================

#[test]
fn test_findings_include_code_snippet_for_single_location() {
    // Create a temp file for snippet extraction test
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("semgrep_snippet_test.txt");
    let content = "line one\nline two\nline three\nline four\nline five\n";

    fs::write(&test_file, content).unwrap();

    let mock_json = format!(
        r#"{{
        "results": [
            {{"check_id": "test.rule", "path": "{}", "start": {{"line": 3}}, "extra": {{"message": "Test issue", "metadata": {{"cwe": ["CWE-1"]}}}}}}
        ]
    }}"#,
        test_file.to_string_lossy()
    );

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    // Code snippet should be present and contain context
    assert!(findings[0].code_snippet.is_some());
    let snippet = findings[0].code_snippet.as_ref().unwrap();
    assert!(snippet.contains("line two"));
    assert!(snippet.contains("line three"));
    assert!(snippet.contains("line four"));
    assert!(snippet.contains(">>")); // Marker for target line

    let _ = fs::remove_file(&test_file);
}

#[test]
fn test_findings_code_snippet_for_nonexistent_file() {
    let mock_json = r#"{
        "results": [
            {"check_id": "test.rule", "path": "/nonexistent/file.py", "start": {"line": 42}, "extra": {"message": "Test"}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    // Should have a snippet even for nonexistent file (with error message)
    assert!(findings[0].code_snippet.is_some());
    let snippet = findings[0].code_snippet.as_ref().unwrap();
    assert!(snippet.contains("file not found") || snippet.contains("Line 42"));
}

#[test]
fn test_aggregated_findings_have_location_list_snippet() {
    let mock_json = r#"{
        "results": [
            {"check_id": "multi.issue", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Issue", "metadata": {}}},
            {"check_id": "multi.issue", "path": "file2.py", "start": {"line": 5}, "extra": {"message": "Issue", "metadata": {}}},
            {"check_id": "multi.issue", "path": "file3.py", "start": {"line": 10}, "extra": {"message": "Issue", "metadata": {}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    // Aggregated findings should have a snippet listing all locations
    assert!(findings[0].code_snippet.is_some());
    let snippet = findings[0].code_snippet.as_ref().unwrap();
    assert!(snippet.contains("3 locations") || snippet.contains("file1.py"));
}

// ============================================================================
// Integration-style Unit Tests
// ============================================================================

#[test]
fn test_full_parse_workflow_with_realistic_json() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.lang.security.critical-dangerous-eval",
                "path": "app.py",
                "start": {"line": 15, "col": 8},
                "end": {"line": 15, "col": 25},
                "extra": {
                    "message": "Use of eval() detected",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-95"],
                        "owasp": ["A1:2017-Injection"]
                    }
                }
            },
            {
                "check_id": "javascript.security.medium-xss",
                "path": "frontend.js",
                "start": {"line": 42, "col": 3},
                "extra": {
                    "message": "Potential XSS vulnerability",
                    "severity": "WARNING",
                    "metadata": {
                        "cwe": ["CWE-79"]
                    }
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 2);

    // Findings may be in any order, so check both
    let first_title = &findings[0].title;
    let second_title = &findings[1].title;

    // One should be the eval finding, the other the xss finding
    assert!(
        (first_title == "python.lang.security.critical-dangerous-eval"
            && second_title == "javascript.security.medium-xss")
            || (first_title == "javascript.security.medium-xss"
                && second_title == "python.lang.security.critical-dangerous-eval")
    );

    // Verify file paths
    assert!(findings[0].file_path == "app.py" || findings[0].file_path == "frontend.js");
    assert!(findings[1].file_path == "app.py" || findings[1].file_path == "frontend.js");
}

#[test]
fn test_parse_with_excluded_rules_in_realistic_scenario() {
    let mock_json = r#"{
        "results": [
            {"check_id": "python.lang.security.insecure-tempfile", "path": "app.py", "start": {"line": 1}, "extra": {"metadata": {}}},
            {"check_id": "python.lang.ast.unused-import", "path": "app.py", "start": {"line": 2}, "extra": {"metadata": {}}},
            {"check_id": "javascript.security.xss.innerhtml", "path": "app.js", "start": {"line": 10}, "extra": {"metadata": {}}}
        ]
    }"#;

    // Exclude python.lang rules
    let runner = SemgrepRunner::new(vec![], vec!["python.lang".to_string()]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // python.lang.* should be excluded, only javascript should remain
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "javascript.security.xss.innerhtml");
}

#[test]
fn test_semgrep_runner_clone_for_async() {
    // Verify SemgrepRunner implements Clone (needed for async spawn_blocking)
    let runner = SemgrepRunner::new(
        vec!["/config.yml".to_string()],
        vec!["rule1".to_string(), "rule2".to_string()],
    );

    let runner_clone = runner.clone();

    assert_eq!(runner.rulesets, runner_clone.rulesets);
    assert_eq!(runner.exclude_rules, runner_clone.exclude_rules);
}
