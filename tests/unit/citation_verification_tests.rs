//! Citation verification unit tests.

use baco::citation_verification::verify_citations;
use baco::findings::{Severity, VulnerabilityFinding};
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

/// Helper to create a VulnerabilityFinding with all required fields.
fn make_finding(file_path: String, line_number: Option<u32>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-001".to_string(),
        title: "Test Finding".to_string(),
        description: "A test vulnerability".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path,
        line_number,
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
fn test_valid_file_and_line() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();
    writeln!(file, "line 2").unwrap();
    writeln!(file, "line 3").unwrap();

    let finding = make_finding("test.rs".to_string(), Some(2));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(findings[0].confidence_score, original_confidence);
    assert!(findings[0].verification_notes.is_none());
}

#[test]
fn test_missing_file() {
    let temp_dir = TempDir::new().unwrap();

    let finding = make_finding("nonexistent.rs".to_string(), Some(1));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(findings[0].confidence_score, original_confidence * 0.5);
    assert!(findings[0].verification_notes.is_some());
    assert!(findings[0]
        .verification_notes
        .as_ref()
        .unwrap()
        .contains("citation verification failed"));
}

#[test]
fn test_line_beyond_eof() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();
    writeln!(file, "line 2").unwrap();

    let finding = make_finding("test.rs".to_string(), Some(10)); // Beyond the 2 lines in file
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(findings[0].confidence_score, original_confidence * 0.5);
    assert!(findings[0].verification_notes.is_some());
    assert!(findings[0]
        .verification_notes
        .as_ref()
        .unwrap()
        .contains("citation verification failed"));
}

#[test]
fn test_no_line_number_with_existing_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();

    let finding = make_finding("test.rs".to_string(), None); // No line number specified
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(findings[0].confidence_score, original_confidence);
    assert!(findings[0].verification_notes.is_none());
}

#[test]
fn test_empty_findings_slice() {
    let temp_dir = TempDir::new().unwrap();

    let mut findings: Vec<VulnerabilityFinding> = vec![];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 0);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 0);
}
