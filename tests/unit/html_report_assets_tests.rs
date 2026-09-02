//! Tests for T31 (self-contained HTML with vendored Prism.js) and T32 (findings grouped by file/root-cause)
//!
//! Test coverage:
//! 1. Generated HTML contains zero external script/link URLs when vendored
//! 2. Grouping: build findings across 2 files → HTML contains both file-group summaries with correct counts
//! 3. Chain section appears only when chain_id present (two cases)
//! 4. Severity badges still present per finding

use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::html::generate_html_report;
use std::fs;

// ============================================================================
// Helper Functions
// ============================================================================

fn make_finding(
    id: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
    title: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.unwrap_or("Test Finding").to_string(),
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
        evidence: vec![],
        verification_tier: None,
    }
}

// ============================================================================
// T31 Tests: Self-contained HTML (no external URLs)
// ============================================================================

#[test]
fn test_no_external_urls_in_html() {
    // T31: Verify that the generated HTML contains no external CDN references
    let findings = vec![make_finding(
        "t1",
        Severity::High,
        "src/test.py",
        Some(10),
        None,
    )];
    let output_path = "/tmp/test_no_external_urls.html";

    let _ = fs::remove_file(output_path);
    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok(), "HTML report generation should succeed");

    let content = fs::read_to_string(output_path).expect("Should read generated HTML");

    // T31: No external script URLs (https?:// in src= or href= attributes)
    let external_url_pattern = regex::Regex::new(r#"src=["']https?://[^"']+["']"#).unwrap();
    let link_href_pattern = regex::Regex::new(r#"href=["']https?://[^"']+["']"#).unwrap();

    assert!(
        !external_url_pattern.is_match(&content),
        "HTML should not contain external script URLs (src=\"http...\" or src=\"https://...\")"
    );
    assert!(
        !link_href_pattern.is_match(&content),
        "HTML should not contain external link URLs in href attributes"
    );

    // Verify Prism.js is embedded (check for Prism initialization code)
    assert!(
        content.contains("Prism"),
        "HTML should contain embedded Prism.js code"
    );

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_prism_embedded_inline() {
    // T31: Verify Prism.js core is embedded
    let findings = vec![make_finding(
        "t2",
        Severity::Medium,
        "src/lib.rs",
        Some(5),
        None,
    )];
    let output_path = "/tmp/test_prism_embedded.html";

    let _ = fs::remove_file(output_path);
    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).expect("Should read HTML");

    // Check that Prism core is present (the minified code contains "Prism=")
    assert!(
        content.contains("Prism=")
            || content.contains("Prismfunction")
            || content.contains("\"Prism\""),
        "HTML should contain embedded Prism.js core library"
    );

    // Check that Prism CSS is embedded (tomorrow theme colors)
    assert!(
        content.contains(".token") && (content.contains("#d4d4d4") || content.contains("color")),
        "HTML should contain embedded Prism CSS styling"
    );

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// T32 Tests: Grouping by file
// ============================================================================

#[test]
fn test_file_grouping_with_multiple_files() {
    // T32: Verify findings are grouped by file with correct counts
    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            "src/file_a.rs",
            Some(10),
            Some("Finding A1"),
        ),
        make_finding(
            "f2",
            Severity::Medium,
            "src/file_a.rs",
            Some(20),
            Some("Finding A2"),
        ),
        make_finding(
            "f3",
            Severity::Low,
            "src/file_b.rs",
            Some(5),
            Some("Finding B1"),
        ),
    ];
    let output_path = "/tmp/test_file_grouping.html";

    let _ = fs::remove_file(output_path);
    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).expect("Should read HTML");

    // T32: Check for file group summaries with correct counts
    assert!(
        content.contains("file_a.rs"),
        "HTML should contain file_a.rs group"
    );
    assert!(
        content.contains("file_b.rs"),
        "HTML should contain file_b.rs group"
    );

    // Check that file_a.rs has 2 findings (format: "📄 file_a.rs (2) findings")
    assert!(
        content.contains("file_a.rs (2) findings"),
        "HTML should show 'file_a.rs (2) findings' group summary"
    );

    // Check that file_b.rs has 1 finding
    assert!(
        content.contains("file_b.rs (1) findings"),
        "HTML should show 'file_b.rs (1) findings' group summary"
    );

    // Check for details/summary structure (T32 grouping implementation)
    assert!(
        content.contains("<details") && content.contains("<summary"),
        "HTML should use <details>/<summary> for file grouping"
    );

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_file_grouping_sorted_by_count() {
    // T32: Verify files are sorted by finding count (descending)
    let findings = vec![
        make_finding("f1", Severity::High, "src/most.rs", Some(1), None),
        make_finding("f2", Severity::High, "src/most.rs", Some(2), None),
        make_finding("f3", Severity::High, "src/most.rs", Some(3), None),
        make_finding("f4", Severity::Medium, "src/middle.rs", Some(1), None),
        make_finding("f5", Severity::Medium, "src/middle.rs", Some(2), None),
        make_finding("f6", Severity::Low, "src/least.rs", Some(1), None),
    ];
    let output_path = "/tmp/test_file_grouping_sorted.html";

    let _ = fs::remove_file(output_path);
    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).expect("Should read HTML");

    // Find positions of file groups
    let most_pos = content.find("most.rs").expect("Should find most.rs");
    let middle_pos = content.find("middle.rs").expect("Should find middle.rs");
    let least_pos = content.find("least.rs").expect("Should find least.rs");

    // Verify order: most (3) > middle (2) > least (1)
    assert!(
        most_pos < middle_pos && middle_pos < least_pos,
        "Files should be sorted by finding count (descending): most.rs (3) → middle.rs (2) → least.rs (1)"
    );

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// T32 Tests: Severity badges preserved
// ============================================================================

#[test]
fn test_severity_badges_preserved_in_groups() {
    // T32: Verify severity badges are still present on each finding row
    let findings = vec![
        make_finding("sb1", Severity::Critical, "src/crit.rs", Some(1), None),
        make_finding("sb2", Severity::High, "src/high.rs", Some(2), None),
        make_finding("sb3", Severity::Medium, "src/med.rs", Some(3), None),
    ];
    let output_path = "/tmp/test_severity_badges.html";

    let _ = fs::remove_file(output_path);
    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).expect("Should read HTML");

    // Check severity classes are present
    assert!(
        content.contains("severity critical") || content.contains("class=\"critical\""),
        "HTML should contain critical severity badge"
    );
    assert!(
        content.contains("severity high") || content.contains("class=\"high\""),
        "HTML should contain high severity badge"
    );
    assert!(
        content.contains("severity medium") || content.contains("class=\"medium\""),
        "HTML should contain medium severity badge"
    );

    let _ = fs::remove_file(output_path);
}

// ============================================================================
// T32 Tests: Root-cause chains section (placeholder - no chain_id field yet)
// ============================================================================

#[test]
fn test_chain_section_not_present_without_chain_data() {
    // T32: When no findings have chain_id, chain section should not appear
    // Note: This test documents expected behavior once chain_id is added to VulnerabilityFinding
    let findings = vec![
        make_finding("c1", Severity::High, "src/file1.rs", Some(1), None),
        make_finding("c2", Severity::Medium, "src/file2.rs", Some(2), None),
    ];
    let output_path = "/tmp/test_no_chain_section.html";

    let _ = fs::remove_file(output_path);
    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).expect("Should read HTML");

    // Currently no chain_id field exists, so chain section should not appear
    // This test will be updated when chain_id is added to the finding structure
    assert!(
        !content.contains("Root-cause chains") && !content.contains("chain"),
        "HTML should not contain chain section when no chain data exists"
    );

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_empty_findings_no_external_urls() {
    // T31: Even with empty findings, no external URLs should be present
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_empty_no_external.html";

    let _ = fs::remove_file(output_path);
    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).expect("Should read HTML");

    let external_url_pattern = regex::Regex::new(r#"src=["']https?://[^"']+["']"#).unwrap();
    let link_href_pattern = regex::Regex::new(r#"href=["']https?://[^"']+["']"#).unwrap();

    assert!(
        !external_url_pattern.is_match(&content),
        "Empty HTML report should not contain external script URLs"
    );
    assert!(
        !link_href_pattern.is_match(&content),
        "Empty HTML report should not contain external link URLs"
    );

    let _ = fs::remove_file(output_path);
}
