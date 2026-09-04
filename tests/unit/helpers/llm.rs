//! LLM verification test helpers.
//!
//! This module consolidates duplicated test helper functions from:
//! - `tests/unit/llm_verification.rs`
//! - `tests/unit/llm_tests_backup/llm_verification_tests.rs`
//!
//! Reduces 98 lines of duplication across 15+ test groups to a single shared implementation.

use baco::findings::VulnerabilityFinding;
use baco::findings::{IssueCategory, SecurityIssue, Severity};

/// Helper to create test findings with customizable parameters.
///
/// This consolidates the duplicated `make_test_finding` function that appears in both
/// `llm_verification.rs` and `llm_tests_backup/llm_verification_tests.rs`.
///
/// # Arguments
/// * `title` - Title of the finding
/// * `severity` - Severity level
/// * `code` - Optional code snippet
///
/// # Returns
/// A `VulnerabilityFinding` with default test values and customizable parameters
pub fn make_test_finding(
    title: &str,
    severity: Severity,
    code: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        description: format!("Test description for {}", title),
        severity,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: code.map(|s| s.to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this issue".to_string()),
        code_location: Some("src/test.rs:42".to_string()),
        already_reported: false,
        sources: vec!["static_analysis".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: Some(SecurityIssue {
            category: IssueCategory::Injection,
            cwe_id: Some("CWE-79".to_string()),
            owasp_category: Some("Injection".to_string()),
            mitre_attack: None,
            custom_tags: vec!["test".to_string()],
        }),
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

/// Creates a test finding with a specific CWE ID.
///
/// # Arguments
/// * `title` - Title of the finding
/// * `severity` - Severity level
/// * `cwe_id` - CWE identifier
/// * `code` - Optional code snippet
///
/// # Returns
/// A `VulnerabilityFinding` with the specified CWE ID
pub fn make_test_finding_with_cwe(
    title: &str,
    severity: Severity,
    cwe_id: &str,
    code: Option<&str>,
) -> VulnerabilityFinding {
    let mut finding = make_test_finding(title, severity, code);
    finding.cwe_id = Some(cwe_id.to_string());
    finding
}

/// Creates a test finding with a specific security issue category.
///
/// # Arguments
/// * `title` - Title of the finding
/// * `severity` - Severity level
/// * `category` - Security issue category
/// * `code` - Optional code snippet
///
/// # Returns
/// A `VulnerabilityFinding` with the specified security issue category
pub fn make_test_finding_with_category(
    title: &str,
    severity: Severity,
    category: IssueCategory,
    code: Option<&str>,
) -> VulnerabilityFinding {
    let mut finding = make_test_finding(title, severity, code);
    finding.security_issue = Some(SecurityIssue {
        category,
        cwe_id: None,
        owasp_category: None,
        mitre_attack: None,
        custom_tags: vec![],
    });
    finding
}
