//! Unit tests for markdown report generation.
//!
//! Tests cover:
//! 1. Empty findings → valid markdown with zero-count summary
//! 2. Two findings different severities → grouped Critical before Low
//! 3. Mitigation code fenced block rendered
//! 4. Evidence tier split — verified in main, unverified in appendix
//! 5. Version string in footer

use baco::evidence::{Evidence, EvidenceSource, VerificationTier};
use baco::findings::Severity;
use baco::report::markdown::generate_markdown_report;
use chrono::Utc;

/// Helper to create a minimal test finding.
fn make_finding(
    id: &str,
    title: &str,
    file: &str,
    line: Option<u32>,
    severity: Severity,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test vulnerability description".to_string(),
        severity,
        confidence_score: 0.85,
        cwe_id: Some(format!("CWE-{}", id.parse::<u32>().unwrap_or(89))),
        file_path: file.to_string(),
        line_number: line,
        code_snippet: None,
        diff_hunk: None,
        recommendation: Some("Apply input validation and parameterized queries.".to_string()),
        code_location: None,
        already_reported: false,
        sources: vec!["semgrep".to_string()],
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

#[test]
fn test_empty_findings_valid_markdown_with_zero_count_summary() {
    let findings: Vec<baco::findings::VulnerabilityFinding> = vec![];
    let report = generate_markdown_report(&findings, "test-project");

    // Should have title
    assert!(
        report.contains("# 🔒 BACO Security Vulnerability Report"),
        "Report should have H1 title"
    );

    // Should have project name and scan date
    assert!(
        report.contains("**Project:** test-project"),
        "Report should have project name"
    );

    // Should have zero total findings
    assert!(
        report.contains("**Total Findings:** 0"),
        "Report should show zero findings"
    );

    // Should have executive summary table with zero counts
    assert!(
        report.contains("| **Critical** | 0 | 0 | 0 | 0 |"),
        "Report should have Critical row with zero counts"
    );

    // Should have "No Findings" section
    assert!(
        report.contains("## No Findings"),
        "Report should have No Findings section"
    );
}

#[test]
fn test_two_findings_different_severities_grouped_critical_before_low() {
    let critical_finding = make_finding(
        "1",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Severity::Critical,
    );
    let low_finding = make_finding("2", "Info Leak", "src/handler.rs", Some(100), Severity::Low);

    // Intentionally create in reverse order to test grouping
    let findings = vec![low_finding, critical_finding];
    let report = generate_markdown_report(&findings, "test-app");

    // Critical should appear before Low in the report
    let critical_pos = report
        .find("## Critical Findings")
        .expect("Should have Critical section");
    let low_pos = report
        .find("## Low Findings")
        .expect("Should have Low section");

    assert!(
        critical_pos < low_pos,
        "Critical findings should appear before Low findings"
    );

    // Both locations should be present
    assert!(
        report.contains("src/db.rs"),
        "Report should contain critical finding location"
    );
    assert!(
        report.contains("src/handler.rs"),
        "Report should contain low finding location"
    );

    // Both titles should be present
    assert!(
        report.contains("SQL Injection"),
        "Report should contain SQL Injection title"
    );
    assert!(
        report.contains("Info Leak"),
        "Report should contain Info Leak title"
    );
}

#[test]
fn test_mitigation_code_fenced_block_rendered() {
    let mut finding = make_finding(
        "3",
        "XSS Vulnerability",
        "src/app.js",
        Some(10),
        Severity::High,
    );
    finding.mitigation_code = Some(
        r#"// Sanitize user input before rendering
const safeOutput = escapeHtml(userInput);
document.body.innerHTML = safeOutput;"#
            .to_string(),
    );
    finding.cwe_id = Some("CWE-79".to_string());

    let findings = vec![finding];
    let report = generate_markdown_report(&findings, "test");

    // Should have Mitigation section
    assert!(
        report.contains("**Mitigation:**"),
        "Report should have Mitigation section"
    );

    // Should have fenced code block with javascript
    assert!(
        report.contains("```javascript"),
        "Report should have javascript code fence"
    );

    // Should contain the mitigation code
    assert!(
        report.contains("escapeHtml(userInput)"),
        "Report should contain mitigation code"
    );
    assert!(
        report.contains("escapeHtml(userInput);"),
        "Report should contain complete mitigation statement"
    );
}

#[test]
fn test_evidence_tier_split_verified_main_unverified_appendix() {
    // Verified finding (has verifier evidence + LLM = 2 kinds)
    let mut verified_finding = make_finding(
        "4",
        "Confirmed RCE",
        "src/exec.rs",
        Some(55),
        Severity::Critical,
    );
    verified_finding.evidence = vec![
        Evidence {
            source: EvidenceSource::LlmAnalysis("static-analysis".to_string()),
            weight: 0.8,
            detail: "LLM identified command injection pattern".to_string(),
            timestamp: Utc::now(),
        },
        Evidence {
            source: EvidenceSource::IndependentVerifier("reproducer".to_string()),
            weight: 0.95,
            detail: "Independent reproducer confirmed exploit".to_string(),
            timestamp: Utc::now(),
        },
    ];
    verified_finding.verification_tier = Some(VerificationTier::Verified);

    // Unverified finding (single LLM source only, low confidence)
    let mut unverified_finding = make_finding(
        "5",
        "Suspected XSS",
        "src/view.rs",
        Some(23),
        Severity::Medium,
    );
    unverified_finding.evidence = vec![Evidence {
        source: EvidenceSource::LlmAnalysis("static-analysis".to_string()),
        weight: 0.4,
        detail: "LLM suspects XSS but lacks concrete evidence".to_string(),
        timestamp: Utc::now(),
    }];
    unverified_finding.confidence_score = 0.5; // Low confidence to ensure Unverified tier
    unverified_finding.verification_tier = Some(VerificationTier::Unverified);

    let findings = vec![verified_finding.clone(), unverified_finding.clone()];
    let report = generate_markdown_report(&findings, "test");

    // Both findings should be in the report
    assert!(
        report.contains("Confirmed RCE"),
        "Verified finding should be in report"
    );
    assert!(
        report.contains("Suspected XSS"),
        "Unverified finding should be in report"
    );

    // Appendix for unverified findings should exist
    assert!(
        report.contains("## Appendix: Unverified Findings"),
        "Report should have unverified appendix"
    );

    // Appendix description should be present
    assert!(
        report.contains("lack sufficient evidence"),
        "Appendix should explain why findings are unverified"
    );

    // Verify tier labels are present
    assert!(
        report.contains("Verified"),
        "Report should show Verified tier"
    );
    assert!(
        report.contains("Unverified"),
        "Report should show Unverified tier"
    );
}

#[test]
fn test_version_string_in_footer() {
    let findings: Vec<baco::findings::VulnerabilityFinding> = vec![];
    let report = generate_markdown_report(&findings, "test");

    let version = env!("CARGO_PKG_VERSION");
    let version_str = format!("v{}", version);

    assert!(
        report.contains(&version_str),
        "Report footer should contain version string: {}",
        version_str
    );

    assert!(
        report.contains("*Generated by BACO Security Scanner"),
        "Report should have generator footer"
    );

    // Footer should be at the end
    let footer_pos = report
        .find(&version_str)
        .expect("Version should be in report");
    let report_len = report.len();
    assert!(
        footer_pos > report_len - 200,
        "Version should be near the end of the report (footer)"
    );
}

#[test]
fn test_executive_summary_table_structure() {
    let findings = vec![
        {
            let mut f = make_finding("6", "Crit1", "a.rs", Some(1), Severity::Critical);
            f.confidence_score = 0.5;
            f
        },
        {
            let mut f = make_finding("7", "Crit2", "b.rs", Some(2), Severity::Critical);
            f.confidence_score = 0.5;
            f
        },
        {
            let mut f = make_finding("8", "High1", "c.rs", Some(3), Severity::High);
            f.confidence_score = 0.5;
            f
        },
    ];
    let report = generate_markdown_report(&findings, "test");

    // Should have table header
    assert!(
        report.contains("| Severity | Verified | Supported | Unverified | Total |"),
        "Report should have executive summary table header"
    );

    // Critical should show 2 total
    assert!(
        report.contains("| **Critical** | 0 | 0 | 2 | 2 |"),
        "Critical row should show 2 findings"
    );

    // High should show 1 total
    assert!(
        report.contains("| **High** | 0 | 0 | 1 | 1 |"),
        "High row should show 1 finding"
    );

    // Medium, Low, Info should show 0
    assert!(
        report.contains("| **Medium** | 0 | 0 | 0 | 0 |"),
        "Medium row should show 0 findings"
    );
    assert!(
        report.contains("| **Low** | 0 | 0 | 0 | 0 |"),
        "Low row should show 0 findings"
    );
    assert!(
        report.contains("| **Info** | 0 | 0 | 0 | 0 |"),
        "Info row should show 0 findings"
    );
}

#[test]
fn test_finding_location_format_with_and_without_line() {
    let with_line = make_finding("9", "With Line", "src/test.rs", Some(42), Severity::High);
    let without_line = make_finding(
        "10",
        "Without Line",
        "src/unknown.rs",
        None,
        Severity::Medium,
    );

    let findings = vec![with_line, without_line];
    let report = generate_markdown_report(&findings, "test");

    // Finding with line should show :42
    assert!(
        report.contains("`src/test.rs`:42"),
        "Finding with line number should show location:line format"
    );

    // Finding without line should show just the path
    assert!(
        report.contains("`src/unknown.rs`"),
        "Finding without line number should show just the path"
    );
}

#[test]
fn test_confidence_score_display() {
    let mut finding = make_finding(
        "11",
        "Confidence Test",
        "src/conf.rs",
        Some(1),
        Severity::Low,
    );
    finding.confidence_score = 0.923;

    let findings = vec![finding];
    let report = generate_markdown_report(&findings, "test");

    // Should show confidence as percentage (92.3%)
    assert!(
        report.contains("**Confidence:** 92.3%"),
        "Report should display confidence score as percentage"
    );
}

#[test]
fn test_cwe_id_in_title() {
    let mut finding = make_finding(
        "89",
        "SQL Injection",
        "src/sql.rs",
        Some(15),
        Severity::High,
    );
    finding.cwe_id = Some("CWE-89".to_string());

    let findings = vec![finding];
    let report = generate_markdown_report(&findings, "test");

    // Title should include CWE in parentheses
    assert!(
        report.contains("### [High] SQL Injection (CWE-89)"),
        "Finding title should include CWE ID"
    );
}

#[test]
fn test_language_detection_for_mitigation() {
    // Test Python file
    let mut py_finding = make_finding("12", "Py Vuln", "app.py", Some(1), Severity::High);
    py_finding.mitigation_code = Some("safe = sanitize(input)".to_string());

    // Test Go file
    let mut go_finding = make_finding("13", "Go Vuln", "main.go", Some(1), Severity::High);
    go_finding.mitigation_code = Some("safe := sanitize(input)".to_string());

    let findings = vec![py_finding, go_finding];
    let report = generate_markdown_report(&findings, "test");

    // Should have python code fence
    assert!(
        report.contains("```python"),
        "Should detect Python language"
    );

    // Should have go code fence
    assert!(report.contains("```go"), "Should detect Go language");
}
