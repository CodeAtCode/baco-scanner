use baco::findings::{Severity, VulnerabilityFinding};
/// Tests for Defect 4: phase error handling in parallel.rs
use baco::scanner::parallel::combine_parallel_results;

fn make_test_finding(id: &str, title: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "A test finding".to_string(),
        file_path: "test.rs".to_string(),
        line_number: Some(10),
        confidence_score: 0.8,
        severity: Severity::Medium,
        cwe_id: Some("CWE-79".to_string()),
        sources: vec!["test".to_string()],
        code_snippet: None,
        verification_status: None,
        cross_file_references: None,
        verification_notes: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
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
fn test_combine_parallel_results_handles_indexing_error() {
    // Create a fake finding
    let findings = vec![make_test_finding("test-1", "Test finding")];

    // Indexing returns an error
    let indexing_result = Some(Err("Indexing failed: no index found".to_string()));

    // Semgrep returns Ok with empty results
    let semgrep_result = Some(Ok((vec![], vec![])));

    // LLM static returns None
    let llm_static_result = None;

    // Should not panic, should log warning and continue
    let (results, _analyzed_files) = combine_parallel_results(
        findings.clone(),
        indexing_result,
        semgrep_result,
        llm_static_result,
    );

    // Should have original findings (indexing error was skipped)
    assert_eq!(results.len(), 1, "Should have original finding");
}

#[test]
fn test_combine_parallel_results_handles_semgrep_error() {
    let findings = vec![make_test_finding("test-1", "Test finding")];

    // Indexing returns Ok with empty results
    let indexing_result = Some(Ok((vec![], vec![])));

    // Semgrep returns an error
    let semgrep_result = Some(Err("Semgrep failed: config error".to_string()));

    // LLM static returns None
    let llm_static_result = None;

    // Should not panic
    let (results, _analyzed_files) = combine_parallel_results(
        findings.clone(),
        indexing_result,
        semgrep_result,
        llm_static_result,
    );

    // Should have original findings
    assert_eq!(results.len(), 1, "Should have original finding");
}

#[test]
fn test_combine_parallel_results_handles_both_errors() {
    let findings = vec![make_test_finding("test-1", "Test finding")];

    // Both return errors
    let indexing_result = Some(Err("Indexing failed".to_string()));
    let semgrep_result = Some(Err("Semgrep failed".to_string()));
    let llm_static_result = None;

    // Should not panic
    let (results, _analyzed_files) = combine_parallel_results(
        findings.clone(),
        indexing_result,
        semgrep_result,
        llm_static_result,
    );

    // Should have original findings
    assert_eq!(results.len(), 1, "Should have original finding");
}

#[test]
fn test_combine_parallel_results_normal_case() {
    let findings = vec![];

    // Normal case: both return Ok with findings
    let index_finding = make_test_finding("index-1", "Index finding");
    let semgrep_finding = make_test_finding("semgrep-1", "Semgrep finding");

    let indexing_result = Some(Ok((vec![index_finding], vec![])));
    let semgrep_result = Some(Ok((vec![semgrep_finding], vec![])));
    let llm_static_result = None;

    let (results, _analyzed_files) =
        combine_parallel_results(findings, indexing_result, semgrep_result, llm_static_result);

    assert_eq!(results.len(), 2, "Should have both findings");
}
