//! Tests for multi-hit Semgrep rule aggregation with real file paths.
//!
//! Verifies that when one rule matches multiple locations, the parser
//! uses the first finding's path/line instead of the "multiple_files" sentinel.

use baco::semgrep::SemgrepRunner;

#[test]
fn test_parse_semgrep_multi_hit_uses_first_path() {
    // One rule matching 2 locations
    let mock_json = r#"{
        "results": [
            {"check_id": "multi.issue", "path": "file1.py", "start": {"line": 10, "col": 5}, "end": {"line": 12}, "extra": {"message": "Issue found", "metadata": {"cwe": ["CWE-79"]}}},
            {"check_id": "multi.issue", "path": "file2.py", "start": {"line": 20, "col": 3}, "end": {"line": 22}, "extra": {"message": "Issue found", "metadata": {"cwe": ["CWE-79"]}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings =
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules)
            .unwrap();

    // Multiple findings with same check_id should be aggregated into one
    assert_eq!(findings.len(), 1);

    // Should use first finding's path, not sentinel
    assert_eq!(findings[0].file_path, "file1.py");
    assert_ne!(findings[0].file_path, "multiple_files");

    // Should have line_number from first finding
    assert_eq!(findings[0].line_number, Some(10));

    // Should have code_location
    assert_eq!(findings[0].code_location, Some("file1.py:10".to_string()));

    // Should have statement_range from first finding
    assert_eq!(findings[0].statement_range, Some((10, 12)));

    // Should have cross_file_references with ALL locations
    let cross_refs = findings[0].cross_file_references.as_ref().unwrap();
    assert_eq!(cross_refs.len(), 2);
    assert!(cross_refs.contains(&"file1.py:10".to_string()));
    assert!(cross_refs.contains(&"file2.py:20".to_string()));

    // ID should be the aggregated hash (different from single-hit generate_id form)
    assert!(findings[0].id.contains("aggregated") || findings[0].id.len() == 64);
    // SHA256 hex
}

#[test]
fn test_parse_semgrep_multi_hit_three_locations() {
    // One rule matching 3 locations
    let mock_json = r#"{
        "results": [
            {"check_id": "triple.issue", "path": "a.rs", "start": {"line": 1}, "end": {"line": 3}, "extra": {"message": "Bug", "metadata": {"cwe": ["CWE-1"]}}},
            {"check_id": "triple.issue", "path": "b.rs", "start": {"line": 5}, "end": {"line": 7}, "extra": {"message": "Bug", "metadata": {"cwe": ["CWE-1"]}}},
            {"check_id": "triple.issue", "path": "c.rs", "start": {"line": 10}, "end": {"line": 12}, "extra": {"message": "Bug", "metadata": {"cwe": ["CWE-1"]}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings =
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules)
            .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "a.rs");
    assert_eq!(findings[0].line_number, Some(1));
    assert_eq!(findings[0].statement_range, Some((1, 3)));

    let cross_refs = findings[0].cross_file_references.as_ref().unwrap();
    assert_eq!(cross_refs.len(), 3);
    assert!(cross_refs.contains(&"a.rs:1".to_string()));
    assert!(cross_refs.contains(&"b.rs:5".to_string()));
    assert!(cross_refs.contains(&"c.rs:10".to_string()));

    // Code snippet should list all locations
    let snippet = findings[0].code_snippet.as_ref().unwrap();
    assert!(snippet.contains("3 files"));
    assert!(snippet.contains("a.rs:1"));
    assert!(snippet.contains("b.rs:5"));
    assert!(snippet.contains("c.rs:10"));
}

#[test]
fn test_parse_semgrep_multi_hit_id_consistency() {
    // Verify that aggregated findings use the deterministic hash-based ID
    let mock_json = r#"{
        "results": [
            {"check_id": "stable.id.test", "path": "x.py", "start": {"line": 1}, "extra": {"message": "X", "metadata": {"cwe": ["CWE-1"]}}},
            {"check_id": "stable.id.test", "path": "y.py", "start": {"line": 2}, "extra": {"message": "Y", "metadata": {"cwe": ["CWE-1"]}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings =
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules)
            .unwrap();

    assert_eq!(findings.len(), 1);
    // ID should be 64-char hex (SHA256)
    assert_eq!(findings[0].id.len(), 64);
    // ID should be deterministic - run again and compare
    let findings2 =
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules)
            .unwrap();
    assert_eq!(findings[0].id, findings2[0].id);
}
