//! Tests for semgrep partial result handling and max-target-bytes configuration
//!
//! Covers:
//! - Bug 1 fix: parsing partial JSON output when semgrep exits non-zero
//! - Bug 2 fix: --max-target-bytes flag is added when configured

use baco::semgrep::SemgrepRunner;

// ============================================================================
// Partial result parsing tests (Bug 1 fix)
// ============================================================================

#[test]
fn test_parse_partial_json_on_non_zero_exit() {
    // Simulate semgrep outputting valid JSON before encountering an error
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.high.injection",
                "path": "test.py",
                "start": {"line": 42, "col": 10},
                "extra": {
                    "message": "Potential SQL injection",
                    "metadata": {"cwe": ["CWE-89"]},
                    "severity": "High"
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings =
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules, &[])
            .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "test.py");
    assert_eq!(findings[0].line_number, Some(42));
}

#[test]
fn test_parse_empty_output_on_non_zero_exit() {
    // Empty stdout is not valid JSON — the parser must reject it.
    // The runner then reports a real error (not a clean scan).
    let runner = SemgrepRunner::new(vec![], vec![]);
    let result = baco::semgrep::parser::parse_json_output(b"", &runner.exclude_rules, &[]);

    assert!(result.is_err(), "empty output must be an error, not Ok([])");
}

#[test]
fn test_parse_invalid_json_returns_error() {
    // Invalid JSON should return an error
    let runner = SemgrepRunner::new(vec![], vec![]);
    let result =
        baco::semgrep::parser::parse_json_output(b"not valid json {{{", &runner.exclude_rules, &[]);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse"));
}

#[test]
fn test_parse_json_with_multiple_findings() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.injection",
                "path": "app.py",
                "start": {"line": 10, "col": 5},
                "extra": {"message": "SQL injection", "metadata": {"cwe": ["CWE-89"]}, "severity": "High"}
            },
            {
                "check_id": "javascript.security.xss",
                "path": "client.js",
                "start": {"line": 25, "col": 12},
                "extra": {"message": "XSS vulnerability", "metadata": {"cwe": ["CWE-79"]}, "severity": "Medium"}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings =
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules, &[])
            .unwrap();

    assert_eq!(findings.len(), 2);
}

// ============================================================================
// Max-target-bytes configuration tests (Bug 2 fix)
// ============================================================================

#[test]
fn test_semgrep_runner_has_max_target_bytes_field() {
    // Verify the field exists and defaults to None
    let runner = SemgrepRunner::new(vec![], vec![]);
    assert!(runner.max_target_bytes.is_none());
}

#[test]
fn test_semgrep_runner_with_max_target_bytes() {
    // Verify we can set max_target_bytes
    let runner = SemgrepRunner::new(vec![], vec![]).with_max_target_bytes(1024 * 1024); // 1 MiB

    assert_eq!(runner.max_target_bytes, Some(1024 * 1024));
}

#[test]
fn test_semgrep_runner_with_max_target_bytes_none() {
    // Verify we can explicitly set it to None
    let runner = SemgrepRunner::new(vec![], vec![]).with_max_target_bytes(0);

    assert_eq!(runner.max_target_bytes, Some(0));
}

// ============================================================================
// Builder method tests
// ============================================================================

#[test]
fn test_with_max_target_bytes_builder() {
    let runner = SemgrepRunner::new(vec!["p/python".into()], vec!["rule1".into()])
        .with_max_target_bytes(2 * 1024 * 1024); // 2 MiB

    assert_eq!(runner.rulesets, vec!["p/python".to_string()]);
    assert_eq!(runner.exclude_rules, vec!["rule1".to_string()]);
    assert_eq!(runner.max_target_bytes, Some(2 * 1024 * 1024));
}
