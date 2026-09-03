//! Unit tests for scanner/helpers.rs
//!
//! Tests cover log_and_aggregate_llm_results function for LLM phase result handling.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::helpers::log_and_aggregate_llm_results;

type RejectedFinding = (VulnerabilityFinding, String);

// Test fixture
fn create_test_finding(title: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title),
        title: title.to_string(),
        description: format!("Test finding: {}", title),
        severity: Severity::Medium,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: "test.rs".to_string(),
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
        evidence: vec![],
        verification_tier: None,
    }
}

#[test]
fn test_log_and_aggregate_some_ok() {
    let llm_result = Some(Ok((
        vec![create_test_finding("finding1")],
        vec!["file1.rs".to_string()],
        Vec::new(),
    )));

    let mut findings = vec![create_test_finding("existing")];
    let mut analyzed_files = vec!["old.rs".to_string()];

    log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

    assert_eq!(findings.len(), 2);
    assert_eq!(analyzed_files, vec!["file1.rs".to_string()]);
}

#[test]
fn test_log_and_aggregate_some_ok_empty_findings() {
    let llm_result = Some(Ok((vec![], vec!["file1.rs".to_string()], Vec::new())));

    let mut findings = vec![create_test_finding("existing")];
    let mut analyzed_files = vec!["old.rs".to_string()];

    log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

    assert_eq!(findings.len(), 1);
    assert_eq!(analyzed_files, vec!["file1.rs".to_string()]);
}

#[test]
fn test_log_and_aggregate_some_err() {
    let llm_result = Some(Err("test error".to_string()));

    let mut findings = vec![create_test_finding("existing")];
    let mut analyzed_files = vec!["old.rs".to_string()];

    log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

    assert_eq!(findings.len(), 1);
    assert_eq!(analyzed_files, vec!["old.rs".to_string()]);
}

#[test]
fn test_log_and_aggregate_none() {
    // Use type alias to avoid complexity warning
    type LlmResult =
        Option<Result<(Vec<VulnerabilityFinding>, Vec<String>, Vec<RejectedFinding>), String>>;
    let llm_result: LlmResult = None;

    let mut findings = vec![create_test_finding("existing")];
    let mut analyzed_files = vec!["old.rs".to_string()];

    log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

    assert_eq!(findings.len(), 1);
    assert_eq!(analyzed_files, vec!["old.rs".to_string()]);
}

#[test]
fn test_log_and_aggregate_multiple_findings() {
    let llm_result = Some(Ok((
        vec![
            create_test_finding("finding1"),
            create_test_finding("finding2"),
            create_test_finding("finding3"),
        ],
        vec!["file1.rs".to_string()],
        Vec::new(),
    )));

    let mut findings = vec![create_test_finding("existing")];
    let mut analyzed_files = vec!["old.rs".to_string()];

    log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

    assert_eq!(findings.len(), 4);
    assert_eq!(analyzed_files, vec!["file1.rs".to_string()]);
}
