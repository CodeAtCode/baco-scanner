//! Test fixtures for security agent verification tests

use crate::findings::{Severity, VulnerabilityFinding};

/// Create a test finding with minimal required fields
pub fn make_finding(title: &str, description: &str, file_path: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.to_lowercase().replace(" ", "-")),
        title: title.to_string(),
        description: description.to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-120".to_string()),
        file_path: file_path.to_string(),
        line_number: Some(42),
        code_snippet: Some("strcpy(buf, input);".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: Some(format!("{}:42", file_path)),
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
        agent_mode: true,
    }
}
