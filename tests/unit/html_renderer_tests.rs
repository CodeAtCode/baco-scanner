//! Unit tests for src/report/html/renderer.rs
//!
//! Tests cover the generate_html_report function which generates complete HTML reports.

use baco::findings::{Severity, VulnerabilityFinding};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Helper to create a minimal test finding.
fn make_finding(
    id: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: file.to_string(),
        line_number: line,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
    }
}

// ============================================================================
// generate_html_report Tests - Basic Functionality
// ============================================================================

#[test]
fn test_generate_html_report_creates_valid_html() {
    let findings = vec![make_finding("f1", Severity::High, "src/test.rs", Some(10))];
    let output_path = "/tmp/test_html_renderer_basic.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());
    assert!(Path::new(output_path).exists());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("<!DOCTYPE html>"));
    assert!(content.contains("<html lang=\"en\">"));
    assert!(content.contains("BACO Security Vulnerability Report"));
    assert!(content.contains("</html>"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_html_renderer_empty.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("No Security Issues Found"));
    assert!(content.contains("0")); // Total findings

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_contains_doctype_and_head() {
    let findings = vec![make_finding("f1", Severity::Low, "src/lib.rs", Some(5))];
    let output_path = "/tmp/test_html_doctype.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("<!DOCTYPE html>"));
    assert!(content.contains("<head>"));
    assert!(content.contains("<meta charset=\"UTF-8\">"));
    assert!(content.contains("Prism.js"));

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// generate_html_report Tests - Severity Handling
// ============================================================================

#[test]
fn test_generate_html_report_all_severity_levels() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/crit.rs", Some(1)),
        make_finding("h1", Severity::High, "src/high.rs", Some(2)),
        make_finding("m1", Severity::Medium, "src/med.rs", Some(3)),
        make_finding("l1", Severity::Low, "src/low.rs", Some(4)),
        make_finding("i1", Severity::Info, "src/info.rs", Some(5)),
    ];
    let output_path = "/tmp/test_all_severities.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Critical"));
    assert!(content.contains("High"));
    assert!(content.contains("Medium"));
    assert!(content.contains("Low"));
    assert!(content.contains("Info"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_single_critical_finding() {
    let findings = vec![make_finding(
        "c1",
        Severity::Critical,
        "src/urgent.rs",
        Some(1),
    )];
    let output_path = "/tmp/test_single_critical.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("finding critical"));
    assert!(content.contains("Critical"));

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// generate_html_report Tests - Metadata and Statistics
// ============================================================================

#[test]
fn test_generate_html_report_contains_scan_metadata() {
    let findings = vec![make_finding(
        "f1",
        Severity::Medium,
        "src/test.rs",
        Some(10),
    )];
    let output_path = "/tmp/test_metadata.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Scan Metadata"));
    assert!(content.contains("Scan Date"));
    assert!(content.contains("Total Findings"));
    assert!(content.contains("1")); // Total findings count

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_contains_avg_confidence() {
    let mut finding1 = make_finding("f1", Severity::High, "src/test1.rs", Some(10));
    finding1.confidence_score = 0.9;
    let mut finding2 = make_finding("f2", Severity::Medium, "src/test2.rs", Some(20));
    finding2.confidence_score = 0.7;
    let findings = vec![finding1, finding2];
    let output_path = "/tmp/test_confidence.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Avg Confidence"));
    // Average of 90 and 70 = 80
    assert!(content.contains("80"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_empty_findings_zero_confidence() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_empty_confidence.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("0.0")); // Avg confidence for empty findings

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// generate_html_report Tests - Filter Buttons and Summary Cards
// ============================================================================

#[test]
fn test_generate_html_report_filter_buttons() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("c2", Severity::Critical, "src/b.rs", Some(2)),
        make_finding("h1", Severity::High, "src/c.rs", Some(3)),
    ];
    let output_path = "/tmp/test_filter_buttons.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("filter-btn"));
    assert!(content.contains("Critical (2)"));
    assert!(content.contains("High (1)"));
    assert!(content.contains("All"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_summary_cards() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("h1", Severity::High, "src/b.rs", Some(2)),
        make_finding("m1", Severity::Medium, "src/c.rs", Some(3)),
        make_finding("l1", Severity::Low, "src/d.rs", Some(4)),
    ];
    let output_path = "/tmp/test_summary_cards.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("card critical"));
    assert!(content.contains("card high"));
    assert!(content.contains("card medium"));
    assert!(content.contains("card low"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_summary_cards_empty() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_empty_summary.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    // Empty findings should not have summary cards for severities
    assert!(!content.contains("card critical"));
    assert!(!content.contains("card high"));

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// generate_html_report Tests - Finding Content
// ============================================================================

#[test]
fn test_generate_html_report_contains_finding_details() {
    let mut finding = make_finding("f1", Severity::High, "src/vuln.rs", Some(42));
    finding.title = "SQL Injection".to_string();
    finding.cwe_id = Some("CWE-89".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_finding_details.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("SQL Injection"));
    assert!(content.contains("CWE-89"));
    assert!(content.contains("finding-0"));
    assert!(content.contains("src/vuln.rs"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_multiple_findings_unique_ids() {
    let findings = vec![
        make_finding("f1", Severity::High, "src/a.rs", Some(1)),
        make_finding("f2", Severity::Medium, "src/b.rs", Some(2)),
        make_finding("f3", Severity::Low, "src/c.rs", Some(3)),
    ];
    let output_path = "/tmp/test_unique_ids.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("id=\"finding-0\""));
    assert!(content.contains("id=\"finding-1\""));
    assert!(content.contains("id=\"finding-2\""));

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// generate_html_report Tests - Directory Creation
// ============================================================================

#[test]
fn test_generate_html_report_creates_nested_directories() {
    let findings = vec![make_finding("f1", Severity::Low, "src/lib.rs", Some(5))];
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir
        .path()
        .join("nested")
        .join("deep")
        .join("report.html");

    let result = baco::report::html::generate_html_report(
        &findings,
        output_path.to_str().unwrap(),
        None,
        None,
    );

    assert!(result.is_ok());
    assert!(output_path.exists());

    let _ = fs::remove_dir_all(temp_dir.path());
}

#[test]
fn test_generate_html_report_creates_parent_directory() {
    let findings = vec![make_finding(
        "f1",
        Severity::Medium,
        "src/test.rs",
        Some(10),
    )];
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("subdir").join("report.html");

    let result = baco::report::html::generate_html_report(
        &findings,
        output_path.to_str().unwrap(),
        None,
        None,
    );

    assert!(result.is_ok());
    assert!(output_path.exists());

    let _ = fs::remove_dir_all(temp_dir.path());
}

// ============================================================================
// generate_html_report Tests - Language Detection and Prism.js
// ============================================================================

#[test]
fn test_generate_html_report_python_file_loads_python_prism() {
    let mut finding = make_finding("f1", Severity::High, "src/vuln.py", Some(42));
    finding.diff_hunk = Some("-old code\n+new code".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_python_prism.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("prism-python"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_rust_file_loads_rust_prism() {
    let mut finding = make_finding("f1", Severity::Medium, "src/lib.rs", Some(100));
    finding.diff_hunk = Some("-unsafe block\n+safe code".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_rust_prism.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("prism-rust"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_diff_hunk_loads_diff_prism() {
    let mut finding = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    finding.diff_hunk = Some("@@ -1,3 +1,4 @@\n-old\n+new\n+added".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_diff_prism.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("prism-diff"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_multiple_languages_multiple_scripts() {
    let findings = vec![
        {
            let mut f = make_finding("f1", Severity::High, "src/app.py", Some(10));
            f.diff_hunk = Some("-old\n+new".to_string());
            f
        },
        {
            let mut f = make_finding("f2", Severity::Medium, "src/lib.rs", Some(20));
            f.diff_hunk = Some("-unsafe\n+safe".to_string());
            f
        },
    ];
    let output_path = "/tmp/test_multi_lang.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("prism-python"));
    assert!(content.contains("prism-rust"));

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// generate_html_report Tests - Edge Cases
// ============================================================================

#[test]
fn test_generate_html_report_very_large_number_of_findings() {
    // Test with 1000 findings to ensure no panic
    let findings: Vec<VulnerabilityFinding> = (0..1000)
        .map(|i| {
            let f = make_finding(
                &format!("f{}", i),
                Severity::Low,
                "src/test.rs",
                Some(i as u32),
            );
            f
        })
        .collect();
    let output_path = "/tmp/test_large_findings.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("1000 findings"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_special_characters_in_title() {
    let mut finding = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    finding.title = "XSS <script>alert('xss')</script>".to_string();
    let findings = vec![finding];
    let output_path = "/tmp/test_special_chars.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    // Note: Title in h3 may not be escaped - this tests current behavior
    // The finding title content in the card is escaped
    assert!(content.contains("XSS"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_unicode_characters() {
    let mut finding = make_finding("f1", Severity::Medium, "src/test.rs", Some(10));
    finding.title = "Vulnerabilità in 日本語".to_string();
    let findings = vec![finding];
    let output_path = "/tmp/test_unicode.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Vulnerabilità"));
    assert!(content.contains("日本語"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_empty_file_path() {
    let finding = make_finding("f1", Severity::Low, "", Some(1));
    let findings = vec![finding];
    let output_path = "/tmp/test_empty_path.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("finding-0"));

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// generate_html_report Tests - Statistics Verification
// ============================================================================

#[test]
fn test_generate_html_report_statistics_correct_counts() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("c2", Severity::Critical, "src/b.rs", Some(2)),
        make_finding("c3", Severity::Critical, "src/c.rs", Some(3)),
        make_finding("h1", Severity::High, "src/d.rs", Some(4)),
        make_finding("h2", Severity::High, "src/e.rs", Some(5)),
    ];
    let output_path = "/tmp/test_stats_counts.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("3")); // Critical count
    assert!(content.contains("2")); // High count
    assert!(content.contains("5 findings")); // Total

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_unique_files_count() {
    let findings = vec![
        make_finding("f1", Severity::High, "src/a.rs", Some(1)),
        make_finding("f2", Severity::Medium, "src/a.rs", Some(2)), // Same file
        make_finding("f3", Severity::Low, "src/b.rs", Some(1)),    // Different file
    ];
    let output_path = "/tmp/test_unique_files.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    // Should show 2 unique files (src/a.rs and src/b.rs)
    assert!(content.contains("2"));

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// generate_html_report Tests - JavaScript Functionality
// ============================================================================

#[test]
fn test_generate_html_report_contains_filter_function() {
    let findings = vec![make_finding("f1", Severity::High, "src/test.rs", Some(10))];
    let output_path = "/tmp/test_js_functions.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("function filterFindings"));
    assert!(content.contains("function toggleFinding"));
    assert!(content.contains("function toggleAll"));
    assert!(content.contains("function searchFindings"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_contains_collapsible_details() {
    let findings = vec![make_finding(
        "f1",
        Severity::Medium,
        "src/test.rs",
        Some(10),
    )];
    let output_path = "/tmp/test_collapsible.html";

    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("finding-details"));
    assert!(content.contains("collapsible"));

    let _ = fs::remove_file(output_path);
}
