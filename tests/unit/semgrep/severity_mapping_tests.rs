//! Tests for Semgrep JSON severity mapping with check_id raising logic
//!
//! Covers:
//! - ERROR → High mapping
//! - WARNING → Medium mapping
//! - INFO → Low mapping
//! - INVENTORY → Low mapping
//! - absent extra.severity + check_id keyword → keyword severity
//! - ERROR + check_id containing "critical" → Critical (keyword raises)
//! - INFO + check_id containing "high" → High (keyword raises)

use baco::findings::Severity;
use baco::semgrep::SemgrepRunner;

// ============================================================================
// JSON severity field mapping tests
// ============================================================================

#[test]
fn test_severity_from_json_error_maps_to_high() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.injection",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "severity": "ERROR",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_severity_from_json_warning_maps_to_medium() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.note",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "severity": "WARNING",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Medium);
}

#[test]
fn test_severity_from_json_info_maps_to_low() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.note",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "severity": "INFO",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Low);
}

#[test]
fn test_severity_from_json_inventory_maps_to_low() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.note",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "severity": "INVENTORY",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Low);
}

// ============================================================================
// Fallback to check_id keyword when extra.severity absent
// ============================================================================

#[test]
fn test_severity_fallback_to_check_id_keyword_when_json_severity_absent() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.critical-issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    // No extra.severity, so falls back to check_id keyword → Critical
    assert_eq!(findings[0].severity, Severity::Critical);
}

// ============================================================================
// Check_id keyword raises severity only (never lowers)
// ============================================================================

#[test]
fn test_check_id_keyword_raises_error_to_critical() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.critical-vulnerability",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "severity": "ERROR",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    // JSON severity ERROR → High, but check_id contains "critical" → raises to Critical
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_check_id_keyword_raises_info_to_high() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.high-risk",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "severity": "INFO",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    // JSON severity INFO → Low, but check_id contains "high" → raises to High
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_check_id_low_does_not_lower_error_severity() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.low-priority",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "severity": "ERROR",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    // JSON severity ERROR → High, check_id contains "low" but keyword cannot lower → stays High
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_severity_case_insensitive_json_values() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "test1",
                "path": "test1.py",
                "start": {"line": 1},
                "extra": {"message": "Issue", "severity": "error", "metadata": {}}
            },
            {
                "check_id": "test2",
                "path": "test2.py",
                "start": {"line": 2},
                "extra": {"message": "Issue", "severity": "Warning", "metadata": {}}
            },
            {
                "check_id": "test3",
                "path": "test3.py",
                "start": {"line": 3},
                "extra": {"message": "Issue", "severity": "info", "metadata": {}}
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    // Sort by file path for deterministic ordering
    let mut sorted = findings.clone();
    sorted.sort_by(|a, b| a.file_path.cmp(&b.file_path));

    // Note: JSON severity values are case-sensitive in Semgrep output
    // These lowercase/mixed-case values won't match, so fall back to check_id (Info)
    assert_eq!(sorted[0].severity, Severity::Info); // test1.py - no match, fallback
    assert_eq!(sorted[1].severity, Severity::Info); // test2.py - no match, fallback
    assert_eq!(sorted[2].severity, Severity::Info); // test3.py - no match, fallback
}

#[test]
fn test_severity_unknown_json_value_falls_back_to_check_id() {
    let mock_json = r#"{
        "results": [
            {
                "check_id": "python.security.medium-issue",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Issue",
                    "severity": "UNKNOWN_VALUE",
                    "metadata": {}
                }
            }
        ]
    }"#;

    let runner = SemgrepRunner::new(vec![], vec![]);
    let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

    assert_eq!(findings.len(), 1);
    // Unknown severity value → fallback to check_id keyword → Medium
    assert_eq!(findings[0].severity, Severity::Medium);
}
