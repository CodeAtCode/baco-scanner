//! Common utilities for integration tests

use baco::findings::{Severity, VulnerabilityFinding};

/// Create a test finding with the specified parameters
///
/// Note: Integration tests cannot import from unit test binaries, so we maintain
/// this minimal copy. For unit tests, use tests::fixtures::create_test_finding instead.
pub fn create_test_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line: u32,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number: Some(line),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
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
