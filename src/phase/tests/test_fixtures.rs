//! Shared test fixtures for all phase tests
//!
//! Centralized fixtures to avoid code duplication across test files.

use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::report::json::LlmMetricsSummary;

/// Create default LLM metrics summary for tests
pub fn create_default_metrics_summary() -> LlmMetricsSummary {
    LlmMetricsSummary {
        total_requests: 0,
        successful_requests: 0,
        failed_requests: 0,
        cached_requests: 0,
        total_tokens: 0,
        avg_latency_ms: 0.0,
        models: vec![],
        operations: vec![],
    }
}

/// Create a minimal test finding with default values
pub fn create_test_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-id".to_string(),
        title: "SQL Injection".to_string(),
        description: "SQL injection vulnerability in user authentication".to_string(),
        severity: Severity::High,
        confidence_score: 0.85,
        cwe_id: Some("CWE-89".to_string()),
        file_path: "src/auth.rs".to_string(),
        line_number: Some(42),
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
    }
}

/// Create a complete finding with all fields populated
pub fn create_complete_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "complete-finding-id".to_string(),
        title: "Complete SQL Injection Finding".to_string(),
        description: "Comprehensive SQL injection vulnerability with all fields populated for testing".to_string(),
        file_path: "src/database.rs".to_string(),
        line_number: Some(42),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: Some("CWE-89".to_string()),
        code_snippet: Some("vulnerable_code()".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix it".to_string()),
        code_location: Some("complete.rs:42".to_string()),
        already_reported: false,
        sources: vec!["semgrep".to_string(), "llm".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.85),
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: Some("Verified".to_string()),
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: Some("llama3.1".to_string()),
        agent_mode: false,
    }
}

/// Create a finding with custom parameters for tests
pub fn create_finding_with_params(
    id: &str,
    severity: Severity,
    confidence: f32,
    file: &str,
    line: Option<u32>,
    cwe: Option<&str>,
    sources: Vec<&str>,
    verification: Option<VerificationStatus>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: confidence,
        cwe_id: cwe.map(String::from),
        file_path: file.to_string(),
        line_number: line,
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
        code_location: None,
        already_reported: false,
        sources: sources.into_iter().map(String::from).collect(),
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
    }
}
