//! Shared utilities and imports for integration and unit tests

use baco::findings::{Severity, VulnerabilityFinding};
use baco::root_cause_dedup::GlobalFpStore;
use tempfile::tempdir;

/// Create a temporary directory for scan data
pub fn create_temp_scan_dir() -> tempfile::TempDir {
    tempdir().expect("Failed to create temporary directory")
}

/// Create a test finding with the specified parameters
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

/// Create a test GlobalFpStore in a temporary directory
pub fn create_test_fp_store() -> GlobalFpStore {
    let temp_dir = create_temp_scan_dir();
    let fp_path = temp_dir.path().join("fp_store.json");
    GlobalFpStore::with_path(&fp_path)
}
