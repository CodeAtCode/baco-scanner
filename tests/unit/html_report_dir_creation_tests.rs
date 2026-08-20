//! Unit tests for HTML report directory creation bug fix
//!
//! Regression tests for the bug where HTML report generation silently failed
//! when the output directory didn't exist (unlike JSON report which creates dirs).
//!
//! Tests cover:
//! - generate_html_report succeeds when output directory does NOT exist (regression test)
//! - generate_html_report succeeds when output directory already exists

use baco::findings::{Severity, VulnerabilityFinding};
use std::fs;
use tempfile::TempDir;

use crate::fixtures::make_finding_html;

fn make_finding(
    id: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
) -> VulnerabilityFinding {
    let mut finding = make_finding_html(id, severity, file, line);
    finding.cwe_id = Some("CWE-79".to_string());
    finding.code_snippet = Some("unsafe code detected".to_string());
    finding.recommendation = Some("Use safe alternatives".to_string());
    finding
}

// ============================================================================
// Regression Test: Directory Creation When Parent Doesn't Exist
// ============================================================================

#[test]
fn test_generate_html_report_creates_nested_directories() {
    // This is the regression test for the silent failure bug.
    // Before the fix, this would fail silently because fs::write doesn't
    // create parent directories, unlike the JSON report writer.
    let findings = vec![make_finding(
        "regression-001",
        Severity::Medium,
        "src/vulnerable.rs",
        Some(42),
    )];

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    // Build a path where even the immediate parent doesn't exist
    let output_path = temp_dir
        .path()
        .join("nested")
        .join("deep")
        .join("report.html");

    // Verify parent directory doesn't exist before the call
    let parent_path = output_path.parent().expect("Expected parent path");
    assert!(
        !parent_path.exists(),
        "Parent directory should not exist before the call"
    );

    // This should succeed and create the nested directories
    let result = baco::report::html::generate_html_report(
        &findings,
        output_path.to_str().expect("Path should be valid UTF-8"),
        None,
        None,
    );

    // The call must succeed (this was the bug - it would fail before)
    assert!(
        result.is_ok(),
        "HTML report generation should succeed even when parent dirs don't exist"
    );

    // Verify the file was actually created on disk
    assert!(
        output_path.exists(),
        "HTML report file should exist on disk after successful generation"
    );

    // Verify the file contains expected HTML content
    let content = fs::read_to_string(&output_path).expect("Failed to read generated HTML file");
    assert!(
        content.contains("BACO Security Report"),
        "HTML should contain report title"
    );
    assert!(
        content.contains("finding-0"),
        "HTML should contain rendered finding"
    );
    assert!(content.contains("CWE-79"), "HTML should contain CWE ID");
}

// ============================================================================
// Positive Test: Directory Already Exists
// ============================================================================

#[test]
fn test_generate_html_report_when_parent_exists() {
    let findings = vec![make_finding(
        "existing-dir-001",
        Severity::High,
        "src/app.rs",
        Some(100),
    )];

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    // Create the parent directory explicitly
    let output_path = temp_dir.path().join("reports").join("report.html");
    let parent_path = output_path.parent().expect("Expected parent path");
    fs::create_dir_all(parent_path).expect("Failed to create parent directory");

    // Verify parent exists before the call
    assert!(
        parent_path.exists(),
        "Parent directory should exist before the call"
    );

    let result = baco::report::html::generate_html_report(
        &findings,
        output_path.to_str().expect("Path should be valid UTF-8"),
        None,
        None,
    );

    assert!(
        result.is_ok(),
        "HTML report generation should succeed when parent exists"
    );
    assert!(
        output_path.exists(),
        "HTML report file should exist on disk"
    );

    // Verify content
    let content = fs::read_to_string(&output_path).expect("Failed to read generated HTML");
    assert!(content.contains("BACO Security Report"));
}

// ============================================================================
// Edge Case: Empty Findings with Non-Existent Directory
// ============================================================================

#[test]
fn test_generate_html_report_empty_findings_no_dir() {
    let findings: Vec<VulnerabilityFinding> = vec![];

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output_path = temp_dir
        .path()
        .join("empty")
        .join("reports")
        .join("report.html");

    // Parent doesn't exist
    assert!(
        !output_path.parent().expect("Expected parent").exists(),
        "Parent should not exist"
    );

    let result = baco::report::html::generate_html_report(
        &findings,
        output_path.to_str().expect("Path should be valid UTF-8"),
        None,
        None,
    );

    assert!(result.is_ok(), "Should succeed even with empty findings");
    assert!(output_path.exists(), "Empty report file should be created");

    let content = fs::read_to_string(&output_path).expect("Failed to read empty report");
    assert!(content.contains("No Security Issues Found"));
}
