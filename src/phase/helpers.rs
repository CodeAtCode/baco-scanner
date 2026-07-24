//! Shared test helpers for phase tests.
//!
//! Note: For new tests in the `tests/` directory, use the fixtures module instead:
//! ```text
//! use tests::fixtures::{create_test_finding, create_finding_with_params, create_test_scanner};
//! ```
//!
//! The functions here are kept for backward compatibility with existing tests in `src/`.

use crate::config::ScannerConfig;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::scanner::Scanner;
use tempfile::TempDir;

/// Create a test vulnerability finding with default values.
///
/// For tests in `tests/` directory, prefer `tests::fixtures::create_test_finding`.
pub fn create_test_finding(
    title: &str,
    file_path: &str,
    line: u32,
    severity: Severity,
) -> VulnerabilityFinding {
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
        statement_range: None,
        triage_verdict: None,
    }
}

/// Create a test vulnerability finding with customizable ID, title, and severity.
///
/// For tests in `tests/` directory, prefer `tests::fixtures::create_finding_with_params`.
pub fn create_finding_with_params(
    id: &str,
    title: &str,
    severity: Severity,
) -> VulnerabilityFinding {
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
        statement_range: None,
        triage_verdict: None,
    }
}

/// Create a test scanner with default configuration.
pub fn create_test_scanner() -> (Scanner, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    (scanner, temp_dir)
}

/// Create a test scanner with a temporary directory.
pub fn create_test_scanner_with_options(
    temp_dir: Option<TempDir>,
    config: Option<ScannerConfig>,
) -> (Scanner, Option<TempDir>) {
    let temp_dir = temp_dir.unwrap_or_else(|| TempDir::new().unwrap());
    let config = config.unwrap_or_default();

    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    (scanner, Some(temp_dir))
}

/// Create a test scanner with default settings.
pub fn create_default_test_scanner() -> (Scanner, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    (scanner, temp_dir)
}

/// Macro to create a test context with scanner and empty analyzed_files.
#[macro_export]
macro_rules! create_ctx {
    () => {{
        let (scanner, temp_dir) = $crate::phase::helpers::create_test_scanner();
        let analyzed_files = Vec::<String>::new();
        let ctx = $crate::phase::PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        (temp_dir, ctx)
    }};
}

/// Macro to create a test context with a finding already added.
#[macro_export]
macro_rules! create_ctx_with_finding {
    ($title:expr, $file:expr, $line:expr, $severity:expr) => {{
        let (scanner, temp_dir) = $crate::phase::helpers::create_test_scanner();
        let finding = $crate::phase::helpers::create_test_finding($title, $file, $line, $severity);
        let scanner_ref = Box::leak(Box::new(scanner));
        scanner_ref.state.send_modify(|s| {
            s.findings.push(finding);
        });
        let analyzed_files = Vec::<String>::new();
        let ctx = $crate::phase::PhaseContext {
            scanner: scanner_ref,
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        (temp_dir, ctx)
    }};
}
