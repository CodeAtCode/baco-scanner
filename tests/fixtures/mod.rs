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

/// Create a test finding with minimal required fields (aggregation test style)
///
/// Used by aggregation and report tests that need customizable severity/confidence.
pub fn make_aggregation_finding(
    id: &str,
    severity: baco::findings::Severity,
    confidence: f32,
    file: &str,
    line: Option<u32>,
    cwe: Option<&str>,
    verification: Option<baco::findings::VerificationStatus>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test finding description".to_string(),
        severity,
        confidence_score: confidence,
        cwe_id: cwe.map(String::from),
        file_path: file.to_string(),
        line_number: line,
        code_snippet: Some("test_code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this issue".to_string()),
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: verification,
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

/// Create a minimal test finding (HTML renderer style)
///
/// Used by HTML rendering tests that need basic finding structure.
pub fn make_finding_html(
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

/// Create a finding with CWE ID (CWE routing test style)
pub fn make_finding_cwe(
    id: &str,
    cwe_id: Option<&str>,
    file_path: &str,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: "test finding".to_string(),
        description: "test".to_string(),
        severity: baco::findings::Severity::Medium,
        confidence_score: 0.5,
        cwe_id: cwe_id.map(String::from),
        file_path: file_path.to_string(),
        line_number: Some(1),
        code_snippet: None,
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

/// Create a finding with code snippet (chain/root-cause test style)
pub fn make_finding_snippet(
    id: &str,
    file_path: &str,
    title: &str,
    code_snippet: Option<&str>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity: baco::findings::Severity::Medium,
        confidence_score: 0.7,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(10),
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["semgrep".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.5),
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

/// Create a finding with severity and sources (confidence test style)
pub fn make_finding_confidence(
    severity: baco::findings::Severity,
    sources: Vec<&str>,
    verification_status: Option<baco::findings::VerificationStatus>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: "test-finding".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.0,
        cwe_id: None,
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: sources.into_iter().map(String::from).collect(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status,
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

/// Create a finding with custom parameters (report aggregation test style)
pub fn make_finding_report_agg(
    id: &str,
    title: &str,
    file_path: &str,
    line_number: Option<u32>,
    cwe_id: Option<&str>,
    severity: baco::findings::Severity,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: cwe_id.map(String::from),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: Some("test_code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this issue".to_string()),
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: Some(baco::findings::VerificationStatus::NeedsReview),
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        agent_mode: false,
        llm_model: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        statement_range: None,
        triage_verdict: None,
    }
}
