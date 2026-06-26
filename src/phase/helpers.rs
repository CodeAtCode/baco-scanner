//! Shared test helpers for phase tests.
//!
//! This module consolidates duplicated test helper functions across phase test files
//! to reduce code duplication from 78 groups to ≤10 groups.

use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};

/// Creates a test vulnerability finding with default values.
///
/// This consolidates 81 lines of duplicated `create_finding` code from 7 phase test files.
///
/// # Arguments
/// * `title` - Title of the finding
/// * `file_path` - Path to the file containing the finding
/// * `line` - Line number where the finding occurs
/// * `severity` - Severity level of the finding
///
/// # Returns
/// A `VulnerabilityFinding` with default test values
pub fn create_test_finding(title: &str, file_path: &str, line: u32, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.replace(' ', "-").to_lowercase()),
        title: title.to_string(),
        description: format!("Test description for {}", title),
        severity,
        confidence_score: 0.0,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(line),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["semgrep".to_string()],
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

/// Creates a test vulnerability finding with customizable ID, title, and severity.
///
/// This consolidates 96 lines of duplicated `create_finding_with_params` code from
/// `confidence_refinement.rs` and `cross_file_analysis.rs`.
///
/// # Arguments
/// * `id` - Unique identifier for the finding
/// * `title` - Title of the finding
/// * `severity` - Severity level of the finding
///
/// # Returns
/// A `VulnerabilityFinding` with the specified parameters and default test values
pub fn create_finding_with_params(id: &str, title: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(10),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: Some(VerificationStatus::NeedsReview),
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

use crate::config::ScannerConfig;
use crate::phase::PhaseContext;
use crate::scanner::Scanner;
use tempfile::TempDir;

/// Creates a test scanner with default configuration.
/// Consolidates duplicated scanner setup code across multiple test files.
pub fn create_test_scanner() -> (Scanner, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    (scanner, temp_dir)
}
