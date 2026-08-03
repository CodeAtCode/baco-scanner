//! Shared fixtures for report tests.
//!
//! This module consolidates duplicate test fixture code across report test files
//! to reduce maintenance overhead and ensure consistency.
//!
//! # Usage
//!
//! ```rust,ignore
//! use tests::unit::report_fixtures::make_finding;
//!
//! #[test]
//! fn test_something() {
//!     let finding = make_finding("f1", Severity::High, "src/test.rs", Some(10));
//! }
//! ```

use baco::findings::{Severity, VulnerabilityFinding};
use baco::root_cause_dedup::GlobalFpStore;
use tempfile::tempdir;

/// Helper to create a minimal test finding.
///
/// This is the primary fixture for report tests. Use this instead of duplicating
/// finding creation code in individual test files.
///
/// # Arguments
/// * `id` - Unique identifier for the finding
/// * `severity` - Severity level
/// * `file` - File path where the finding occurs
/// * `line` - Optional line number
///
/// # Example
///
/// ```rust,ignore
/// use tests::unit::report_fixtures::make_finding;
/// use baco::findings::Severity;
///
/// let finding = make_finding("f1", Severity::High, "src/test.rs", Some(10));
/// ```
pub fn make_finding(
    id: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_finding_basic() {
        let finding = make_finding("test-1", Severity::High, "src/test.rs", Some(42));

        assert_eq!(finding.id, "test-1");
        assert_eq!(finding.title, "Finding test-1");
        assert_eq!(finding.file_path, "src/test.rs");
        assert_eq!(finding.line_number, Some(42));
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_make_finding_without_line() {
        let finding = make_finding("test-2", Severity::Critical, "src/main.rs", None);

        assert_eq!(finding.id, "test-2");
        assert!(finding.line_number.is_none());
    }
}
