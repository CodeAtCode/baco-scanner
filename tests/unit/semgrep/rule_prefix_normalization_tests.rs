//! Tests for Semgrep rule ID prefix normalization
//!
//! Covers:
//! - Stripping temp-file stem prefixes from check_ids
//! - Preserving unprefixed check_ids unchanged
//! - Aggregation path with prefixed ids
//! - Severity mapping unaffected by normalization

use baco::findings::Severity;
use baco::semgrep::parser::strip_rule_prefix;
use baco::semgrep::SemgrepRunner;

// ============================================================================
// Unit tests for strip_rule_prefix function
// ============================================================================

#[test]
fn test_strip_prefix_exact_match() {
    let stems = vec!["tmpabc123".to_string()];
    let result = strip_rule_prefix("tmpabc123-cpp-strcpy-high", &stems);
    assert_eq!(result, "cpp-strcpy-high");
}

#[test]
fn test_strip_prefix_no_match() {
    let stems = vec!["tmpabc123".to_string()];
    let result = strip_rule_prefix("python.security.injection", &stems);
    assert_eq!(result, "python.security.injection");
}

#[test]
fn test_strip_prefix_empty_stems() {
    let stems: Vec<String> = vec![];
    let result = strip_rule_prefix("tmpabc123-cpp-strcpy-high", &stems);
    assert_eq!(result, "tmpabc123-cpp-strcpy-high");
}

#[test]
fn test_strip_prefix_multiple_stems() {
    let stems = vec![
        "stem1".to_string(),
        "stem2".to_string(),
        "tmpabc123".to_string(),
    ];
    let result = strip_rule_prefix("tmpabc123-cpp-strcpy-high", &stems);
    assert_eq!(result, "cpp-strcpy-high");
}

#[test]
fn test_strip_prefix_partial_stem_no_match() {
    let stems = vec!["tmp".to_string()];
    // "tmp" is a prefix but not a stem prefix (needs "-")
    let result = strip_rule_prefix("tmpabc123-cpp-strcpy-high", &stems);
    assert_eq!(result, "tmpabc123-cpp-strcpy-high");
}

#[test]
fn test_strip_prefix_empty_remainder_unchanged() {
    let stems = vec!["tmpabc123".to_string()];
    // Stem prefix with empty remainder should be unchanged
    let result = strip_rule_prefix("tmpabc123-", &stems);
    assert_eq!(result, "tmpabc123-");
}

#[test]
fn test_strip_prefix_empty_check_id() {
    let stems = vec!["tmpabc123".to_string()];
    let result = strip_rule_prefix("", &stems);
    assert_eq!(result, "");
}

#[test]
fn test_strip_prefix_with_special_chars() {
    let stems = vec!["baco-rules-0".to_string()];
    let result = strip_rule_prefix("baco-rules-0-critical-vuln-high", &stems);
    assert_eq!(result, "critical-vuln-high");
}

// ============================================================================
// Integration tests: prefixed ids in parsed findings
// ============================================================================

#[test]
fn test_parse_prefixed_id_normalizes_title() {
    // Simulate Semgrep output with prefixed check_id from temp file
    let mock_json = r#"{
        "results": [
            {
                "check_id": "tmpabc123-cpp-strcpy-high",
                "path": "vulnerable.c",
                "start": {"line": 42},
                "extra": {
                    "message": "Unsafe strcpy detected",
                    "metadata": {"cwe": ["CWE-120"]}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    // Pass stems that match the prefix
    let findings = baco::semgrep::parser::parse_json_output(
        mock_json.as_bytes(),
        &runner.exclude_rules,
        &["tmpabc123".to_string()],
    )
    .unwrap();

    assert_eq!(findings.len(), 1);
    // Title should be normalized (prefix stripped)
    assert_eq!(findings[0].title, "cpp-strcpy-high");
    assert_eq!(findings[0].file_path, "vulnerable.c");
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_parse_unprefixed_id_unchanged() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.injection-high",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {
                    "message": "SQL injection",
                    "metadata": {"cwe": ["CWE-89"]}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = baco::semgrep::parser::parse_json_output(
        mock_json.as_bytes(),
        &runner.exclude_rules,
        &["tmpabc123".to_string()],
    )
    .unwrap();

    assert_eq!(findings.len(), 1);
    // Unprefixed id should remain unchanged
    assert_eq!(findings[0].title, "python.security.injection-high");
}

#[test]
fn test_parse_mixed_prefixed_and_unprefixed() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "tmpabc123-cpp-memcpy-high",
                "path": "file1.c",
                "start": {"line": 5},
                "extra": {"message": "Memcpy issue", "metadata": {}}
            },
            {
                "check_id": "javascript.security.xss-medium",
                "path": "file2.js",
                "start": {"line": 20},
                "extra": {"message": "XSS issue", "metadata": {}}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = baco::semgrep::parser::parse_json_output(
        mock_json.as_bytes(),
        &runner.exclude_rules,
        &["tmpabc123".to_string()],
    )
    .unwrap();

    assert_eq!(findings.len(), 2);
    // Sort by title for deterministic ordering
    let mut sorted = findings.clone();
    sorted.sort_by(|a, b| a.title.cmp(&b.title));

    assert_eq!(sorted[0].title, "cpp-memcpy-high"); // Prefixed, normalized
    assert_eq!(sorted[1].title, "javascript.security.xss-medium"); // Unprefixed
}

// ============================================================================
// Aggregation path tests with prefixed ids
// ============================================================================

#[test]
fn test_aggregation_prefixed_ids_normalize() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "tmpxyz-cpp-buffer-overflow-high",
                "path": "file1.c",
                "start": {"line": 10},
                "extra": {"message": "Buffer overflow", "metadata": {"cwe": ["CWE-119"]}}
            },
            {
                "check_id": "tmpxyz-cpp-buffer-overflow-high",
                "path": "file2.c",
                "start": {"line": 25},
                "extra": {"message": "Buffer overflow", "metadata": {"cwe": ["CWE-119"]}}
            },
            {
                "check_id": "tmpxyz-cpp-buffer-overflow-high",
                "path": "file3.c",
                "start": {"line": 40},
                "extra": {"message": "Buffer overflow", "metadata": {"cwe": ["CWE-119"]}}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = baco::semgrep::parser::parse_json_output(
        mock_json.as_bytes(),
        &runner.exclude_rules,
        &["tmpxyz".to_string()],
    )
    .unwrap();

    // Multiple findings with same check_id should aggregate
    assert_eq!(findings.len(), 1);
    // Title should be normalized
    assert_eq!(findings[0].title, "cpp-buffer-overflow-high");
    assert_eq!(findings[0].cwe_id, Some("CWE-119".to_string()));
}

// ============================================================================
// Severity mapping unaffected by normalization
// ============================================================================

#[test]
fn test_severity_mapping_with_prefixed_id() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "tmpstem-critical-vuln",
                "path": "test.c",
                "start": {"line": 1},
                "extra": {"message": "Critical", "metadata": {}}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = baco::semgrep::parser::parse_json_output(
        mock_json.as_bytes(),
        &runner.exclude_rules,
        &["tmpstem".to_string()],
    )
    .unwrap();

    assert_eq!(findings.len(), 1);
    // Severity should still be detected from the normalized id (contains "critical")
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_severity_mapping_high_keyword_after_normalization() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "baco-rules-0-cpp-memcpy-variable-size-high",
                "path": "test.c",
                "start": {"line": 1},
                "extra": {"message": "High risk", "metadata": {}}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = baco::semgrep::parser::parse_json_output(
        mock_json.as_bytes(),
        &runner.exclude_rules,
        &["baco-rules-0".to_string()],
    )
    .unwrap();

    assert_eq!(findings.len(), 1);
    // After normalization: "cpp-memcpy-variable-size-high" contains "high"
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_severity_mapping_medium_keyword_after_normalization() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "tmp123-python-medium-issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Medium", "metadata": {}}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = baco::semgrep::parser::parse_json_output(
        mock_json.as_bytes(),
        &runner.exclude_rules,
        &["tmp123".to_string()],
    )
    .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Medium);
}

#[test]
fn test_severity_mapping_low_keyword_after_normalization() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "stem-low-priority-note",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {"message": "Low", "metadata": {}}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = baco::semgrep::parser::parse_json_output(
        mock_json.as_bytes(),
        &runner.exclude_rules,
        &["stem".to_string()],
    )
    .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Low);
}
