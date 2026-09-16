//! Unit tests for scanner/helpers.rs
//!
//! Tests cover log_and_aggregate_llm_results function for LLM phase result handling.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::helpers::log_and_aggregate_llm_results;

use crate::fixtures::make_finding_report_agg;

type RejectedFinding = (VulnerabilityFinding, String);

// Test fixture
fn create_test_finding(title: &str) -> VulnerabilityFinding {
    let mut f = make_finding_report_agg(
        &format!("test-{}", title),
        title,
        "test.rs",
        Some(1),
        None,
        Severity::Medium,
    );
    f.description = format!("Test finding: {}", title);
    f
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
