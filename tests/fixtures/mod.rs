//! Centralized test fixtures for baco test suite.
//!
//! This module consolidates duplicate test fixture code to reduce maintenance
//! overhead and ensure consistency across test files.

#![allow(dead_code)] // Some helpers are only used by unit tests, not integration tests

/// Helper to create a VulnerabilityFinding for unit tests (multi_verifier/root_cause_dedup style)
///
/// This matches the signature used in tests/unit/multi_verifier_phase_tests.rs
/// and tests/unit/root_cause_dedup_phase_tests.rs.
pub fn make_finding_phase(
    id: &str,
    title: &str,
    file_path: &str,
    line_number: Option<u32>,
    code_snippet: Option<&str>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test description".to_string(),
        severity: baco::findings::Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.9),
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

/// Helper to create a minimal test finding for report tests.
///
/// This matches the signature used in tests/unit/report_fixtures.rs.
pub fn make_finding_report(
    id: &str,
    severity: baco::findings::Severity,
    file: &str,
    line: Option<u32>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
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

/// Create a test finding with the specified parameters (integration test style)
///
/// This matches the signature used in tests/integration/common.rs.
pub fn create_test_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line: u32,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity: baco::findings::Severity::High,
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
