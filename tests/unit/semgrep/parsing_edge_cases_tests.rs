//! Edge case tests for Semgrep JSON parsing
//!
//! These tests cover malformed, incomplete, and unusual JSON structures
//! to ensure the parser handles them gracefully without panicking.
//!
//! Covers:
//! - Missing required fields (check_id, extra, start)
//! - Empty results arrays
//! - Malformed location objects
//! - Invalid line numbers (negative, zero, non-integer)
//! - Nested JSON with missing fields
//! - Very long code snippets
//! - Unicode characters in paths and code

use baco::semgrep::SemgrepRunner;

// ============================================================================
// Test 1: Missing check_id field in result
// ============================================================================

#[test]
fn test_missing_check_id_field() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "path": "test.py",
                "start": {"line": 42, "col": 10},
                "extra": {
                    "message": "Missing check_id",
                    "metadata": {"cwe": ["CWE-1"]}
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    // Result without check_id should be skipped
    assert!(
        findings.is_empty(),
        "Results with missing check_id should be skipped"
    );
}

// ============================================================================
// Test 2: Missing extra block in result
// ============================================================================

#[test]
fn test_missing_extra_block() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42, "col": 10}
                // No "extra" block at all
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    // Should handle missing extra gracefully with defaults
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "test.rule");
    assert_eq!(findings[0].severity, baco::findings::Severity::Info); // Default
    assert!(findings[0].cwe_id.is_none());
    assert!(findings[0].description.contains("test.rule")); // Fallback description
}

// ============================================================================
// Test 3: Empty results array
// ============================================================================

#[test]
fn test_empty_results_array() {
    let mock_json = serde_json::json!({
        "results": []
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert!(
        findings.is_empty(),
        "Empty results should produce no findings"
    );
}

// ============================================================================
// Test 4: Malformed start object (missing line/column)
// ============================================================================

#[test]
fn test_malformed_start_missing_line() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"col": 10} // Missing line
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    // Missing line should skip the result
    assert!(
        findings.is_empty(),
        "Results with missing start.line should be skipped"
    );
}

#[test]
fn test_malformed_start_empty_object() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {} // Empty start object
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    // Empty start object should skip the result
    assert!(
        findings.is_empty(),
        "Results with empty start should be skipped"
    );
}

#[test]
fn test_malformed_start_null_value() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": null
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    // Null start should skip the result
    assert!(
        findings.is_empty(),
        "Results with null start should be skipped"
    );
}

// ============================================================================
// Test 5: Invalid line numbers (negative, zero, non-integer)
// ============================================================================

#[test]
fn test_invalid_line_number_zero() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 0, "col": 10}
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    // Line 0 is technically invalid but serde_json parses it as u64
    // The parser should handle it (may produce a finding at line 0)
    // This tests that we don't panic on zero
    assert!(findings.len() <= 1, "Should handle zero line without panic");
}

#[test]
fn test_invalid_line_number_negative() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": -1, "col": 10}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(None, vec![]);
    // Negative line number won't parse as u64, so result should be skipped
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert!(
        findings.is_empty(),
        "Negative line numbers should be skipped"
    );
}

#[test]
fn test_invalid_line_number_non_integer() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": "not a number", "col": 10}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(None, vec![]);
    // String line number won't parse as u64, so result should be skipped
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert!(
        findings.is_empty(),
        "Non-integer line numbers should be skipped"
    );
}

#[test]
fn test_invalid_line_number_float() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42.5, "col": 10}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(None, vec![]);
    // Float line number won't parse as u64, so result should be skipped
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert!(findings.is_empty(), "Float line numbers should be skipped");
}

// ============================================================================
// Test 6: Nested JSON structures with missing fields
// ============================================================================

#[test]
fn test_nested_missing_metadata() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Has message but no metadata"
                    // No metadata field
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].cwe_id.is_none(),
        "Missing metadata should result in no CWE"
    );
    assert_eq!(findings[0].description, "Has message but no metadata");
}

#[test]
fn test_nested_missing_cwe_array() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Has metadata but no CWE",
                    "metadata": {}
                    // No cwe field
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].cwe_id.is_none(),
        "Missing cwe in metadata should result in no CWE"
    );
}

#[test]
fn test_nested_empty_cwe_array() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Has empty CWE array",
                    "metadata": {"cwe": []}
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].cwe_id.is_none(),
        "Empty cwe array should result in no CWE"
    );
}

#[test]
fn test_nested_null_metadata() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Has null metadata",
                    "metadata": null
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].cwe_id.is_none(),
        "Null metadata should result in no CWE"
    );
}

// ============================================================================
// Test 7: Very long code snippets (>1000 chars)
// ============================================================================

#[test]
fn test_very_long_check_id() {
    let long_id = "a".repeat(1000);
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": long_id,
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Rule with very long ID"
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].title.len(),
        1000,
        "Should preserve long check_id"
    );
}

#[test]
fn test_very_long_message() {
    let long_message = "x".repeat(2000);
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": long_message
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].description.len(),
        2000,
        "Should preserve long message"
    );
}

// Create a temp file with long content for snippet testing
#[test]
fn test_very_long_file_path() {
    let long_path = format!("/tmp/{}", "a".repeat(200));
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": long_path,
                "start": {"line": 1},
                "extra": {
                    "message": "Long path test"
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    // File not found, but should not panic
    assert!(findings[0].code_snippet.is_some());
    assert!(findings[0]
        .code_snippet
        .as_ref()
        .unwrap()
        .contains("file not found"));
}

// ============================================================================
// Test 8: Unicode characters in file paths and code snippets
// ============================================================================

#[test]
fn test_unicode_in_file_path() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "/path/à la mode/文件/test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Unicode path test"
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].file_path.contains("文件"),
        "Should preserve Unicode in path"
    );
    assert!(
        findings[0].file_path.contains("à la mode"),
        "Should preserve Unicode in path"
    );
}

#[test]
fn test_unicode_in_check_id() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "日本語.security.issue",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Unicode check_id"
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "日本語.security.issue");
}

#[test]
fn test_unicode_in_message() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Found 🚨 vulnerability with émojis and ñoñas"
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].description.contains("🚨"));
    assert!(findings[0].description.contains("ñ"));
}

#[test]
fn test_unicode_cwe_metadata() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Test",
                    "metadata": {
                        "cwe": ["CWE-日本語"]
                    }
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cwe_id, Some("CWE-日本語".to_string()));
}

#[test]
fn test_mixed_unicode_and_ascii() {
    let mock_json = serde_json::json!({
        "results": [
            {
                "check_id": "python.security.注入",
                "path": "/home/用户/app.py",
                "start": {"line": 42, "col": 10},
                "extra": {
                    "message": "SQL 注入 detected in 代码",
                    "metadata": {
                        "cwe": ["CWE-89"]
                    }
                }
            }
        ]
    });

    let runner = SemgrepRunner::new(None, vec![]);
    let findings = runner
        .parse_json_output(mock_json.to_string().as_bytes())
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("注入"));
    assert!(findings[0].file_path.contains("用户"));
    assert!(findings[0].description.contains("注入"));
    assert_eq!(findings[0].cwe_id, Some("CWE-89".to_string()));
}
