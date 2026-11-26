//! Shared test helpers for phase tests.
//!
//! Note: For new tests in the `tests/` directory, use the fixtures module instead:
//! ```text
//! use tests::fixtures::{create_test_finding, create_finding_with_params, create_test_finding_simple};
//! ```

use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};

/// Create a test vulnerability finding with default values.
///
/// For tests in `tests/` directory, prefer `tests::fixtures::create_test_finding`.
pub fn create_test_finding(
    title: &str,
    file_path: &str,
    line: u32,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.replace(' ', "-").to_lowercase()),
        title: title.to_string(),
        description: format!("Test description for {}", title),
        severity,
        confidence_score: 0.0,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(line),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        sources: vec!["semgrep".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        related_finding_ids: None,
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
        verification_gate_answers: None,
    }
}

/// Convenience wrapper creating a test finding with default file/line.
///
/// For tests in `tests/` directory, prefer `tests::fixtures::create_test_finding`.
pub fn create_test_finding_simple(title: &str, severity: Severity) -> VulnerabilityFinding {
    create_test_finding(title, "src/test.rs", 42, severity)
}

/// Create a test vulnerability finding with customizable ID, title, and severity.
///
/// For tests in `tests/` directory, prefer `tests::fixtures::create_finding_with_params`.
pub fn create_finding_with_params(
    id: &str,
    title: &str,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(10),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
        code_location: None,
        sources: Vec::new(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        related_finding_ids: None,
        verification_status: Some(VerificationStatus::NeedsReview),
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
        verification_gate_answers: None,
    }
}
