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
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules, &[])
            .unwrap();

    // Multiple findings with same check_id but different paths/lines are SEPARATE findings
    assert_eq!(findings.len(), 2);

    // Sort by file_path for deterministic ordering
    let mut sorted = findings.clone();
    sorted.sort_by(|a, b| a.file_path.cmp(&b.file_path));

    // Check first finding (file1.py:10)
    assert_eq!(sorted[0].file_path, "file1.py");
    assert_eq!(sorted[0].line_number, Some(10));
    assert_eq!(sorted[0].code_location, Some("file1.py:10".to_string()));
    assert_eq!(sorted[0].statement_range, Some((10, 12)));

    // Check second finding (file2.py:20)
    assert_eq!(sorted[1].file_path, "file2.py");
    assert_eq!(sorted[1].line_number, Some(20));
    assert_eq!(sorted[1].code_location, Some("file2.py:20".to_string()));
    assert_eq!(sorted[1].statement_range, Some((20, 22)));

    // Each finding has cross_file_references: None (single-location findings)
    assert!(sorted[0].cross_file_references.is_none());
    assert!(sorted[1].cross_file_references.is_none());

    // Each finding has a regular generate_id (NOT "aggregated" hash)
    assert!(!sorted[0].id.contains("aggregated"));
    assert!(!sorted[1].id.contains("aggregated"));
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
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules, &[])
            .unwrap();

    // Three separate findings (one per location)
    assert_eq!(findings.len(), 3);

    // Sort by file_path for deterministic ordering
    let mut sorted = findings.clone();
    sorted.sort_by(|a, b| a.file_path.cmp(&b.file_path));

    // Check each finding has correct path and line
    assert_eq!(sorted[0].file_path, "a.rs");
    assert_eq!(sorted[0].line_number, Some(1));
    assert_eq!(sorted[0].statement_range, Some((1, 3)));

    assert_eq!(sorted[1].file_path, "b.rs");
    assert_eq!(sorted[1].line_number, Some(5));
    assert_eq!(sorted[1].statement_range, Some((5, 7)));

    assert_eq!(sorted[2].file_path, "c.rs");
    assert_eq!(sorted[2].line_number, Some(10));
    assert_eq!(sorted[2].statement_range, Some((10, 12)));

    // Each finding has its own code snippet from its own file
    assert!(sorted[0].code_snippet.is_some());
    assert!(sorted[1].code_snippet.is_some());
    assert!(sorted[2].code_snippet.is_some());
}

#[test]
fn test_parse_semgrep_multi_hit_id_consistency() {
    // Verify that findings use deterministic IDs
    let mock_json = r#"{
        "results": [
            {"check_id": "stable.id.test", "path": "x.py", "start": {"line": 1}, "extra": {"message": "X", "metadata": {"cwe": ["CWE-1"]}}},
            {"check_id": "stable.id.test", "path": "y.py", "start": {"line": 2}, "extra": {"message": "Y", "metadata": {"cwe": ["CWE-1"]}}}
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings =
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules, &[])
            .unwrap();

    // Two separate findings
    assert_eq!(findings.len(), 2);

    // IDs should be deterministic - run again and compare
    let findings2 =
        baco::semgrep::parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules, &[])
            .unwrap();

    // Sort both by file_path before comparing
    let mut sorted1 = findings.clone();
    sorted1.sort_by(|a, b| a.file_path.cmp(&b.file_path));
    let mut sorted2 = findings2.clone();
    sorted2.sort_by(|a, b| a.file_path.cmp(&b.file_path));

    assert_eq!(sorted1[0].id, sorted2[0].id);
    assert_eq!(sorted1[1].id, sorted2[1].id);
}
