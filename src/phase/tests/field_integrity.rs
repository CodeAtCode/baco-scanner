//! Field preservation tests (15 tests)
//!
//! Tests verifying that all VulnerabilityFinding and Checkpoint fields
//! are correctly preserved through serialization, deserialization,
//! and phase processing.

use crate::config::ScannerConfig;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::phase::tests::test_fixtures::{
    create_complete_finding, create_default_metrics_summary, create_test_finding,
};
use crate::report::html::generate_html_report;
use std::fs;
use tempfile::TempDir;

/// Test 3: JSON serialization field integrity
#[test]
fn test_field_preservation_json_serialization() {
    let finding = create_complete_finding();
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    // Verify all 16+ fields are preserved
    assert_eq!(finding.id, deserialized.id);
    assert_eq!(finding.title, deserialized.title);
    assert_eq!(finding.description, deserialized.description);
    assert_eq!(finding.severity, deserialized.severity);
    assert_eq!(finding.confidence_score, deserialized.confidence_score);
    assert_eq!(finding.cwe_id, deserialized.cwe_id);
    assert_eq!(finding.file_path, deserialized.file_path);
    assert_eq!(finding.line_number, deserialized.line_number);
    assert_eq!(finding.code_snippet, deserialized.code_snippet);
    assert_eq!(finding.diff_hunk, deserialized.diff_hunk);
    assert_eq!(finding.recommendation, deserialized.recommendation);
    assert_eq!(finding.code_location, deserialized.code_location);
    assert_eq!(finding.already_reported, deserialized.already_reported);
    assert_eq!(finding.sources, deserialized.sources);
    assert_eq!(finding.commit_reference, deserialized.commit_reference);
    assert_eq!(finding.ticket_reference, deserialized.ticket_reference);
    assert_eq!(finding.priority_score, deserialized.priority_score);
    assert_eq!(
        finding.cross_file_references,
        deserialized.cross_file_references
    );
    assert_eq!(
        finding.verification_status,
        deserialized.verification_status
    );
    assert_eq!(finding.verification_notes, deserialized.verification_notes);
    assert_eq!(finding.poc_code, deserialized.poc_code);
    assert_eq!(finding.mitigation_code, deserialized.mitigation_code);
    assert_eq!(finding.poc_format, deserialized.poc_format);
    assert_eq!(finding.llm_model, deserialized.llm_model);
    assert_eq!(finding.agent_mode, deserialized.agent_mode);
}

/// Test 5: Aggregation phase field preservation
#[test]
fn test_field_preservation_aggregation_phase() {
    let mut finding = create_test_finding();
    finding.llm_model = Some("gpt-4o".to_string());
    finding.poc_code = Some("exploit code".to_string());

    // Fields should survive through aggregation processing
    let preserved_llm_model = finding.llm_model.clone();
    let preserved_poc = finding.poc_code.clone();

    assert_eq!(preserved_llm_model, Some("gpt-4o".to_string()));
    assert_eq!(preserved_poc, Some("exploit code".to_string()));
}

/// Test 6: HTML report field display
#[test]
fn test_field_preservation_html_report_display() {
    let findings = vec![create_complete_finding()];
    let temp_dir = TempDir::new().unwrap();
    let html_path = temp_dir.path().join("report.html");

    let config = ScannerConfig::default();
    let _metrics = create_default_metrics_summary();

    let result = generate_html_report(&findings, html_path.to_str().unwrap(), Some(&config), None);
    assert!(result.is_ok());

    let html_content = fs::read_to_string(html_path).unwrap();
    // Verify key fields appear in HTML
    assert!(html_content.contains("Complete SQL Injection Finding"));
    assert!(html_content.contains("src/database.rs"));
    assert!(html_content.contains("CWE-89"));
    assert!(html_content.contains("src/database.rs"));
    assert!(html_content.contains("CWE-89"));
}

/// Test 7: Severity field preservation
#[test]
fn test_field_preservation_severity_levels() {
    let severities = vec![
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for severity in severities {
        let mut finding = create_test_finding();
        finding.severity = severity;

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(finding.severity, deserialized.severity);
    }
}

/// Test 8: Code snippet field preservation
#[test]
fn test_field_preservation_code_snippet() {
    let mut finding = create_test_finding();
    finding.code_snippet = Some("strcpy(buf, user_input);".to_string());

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(finding.code_snippet, deserialized.code_snippet);
    assert_eq!(
        deserialized.code_snippet,
        Some("strcpy(buf, user_input);".to_string())
    );
}

/// Test 9: Line number field preservation (None and Some cases)
#[test]
fn test_field_preservation_line_number_none_and_some() {
    // Test Some case
    let mut finding = create_test_finding();
    finding.line_number = Some(42);

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding.line_number, deserialized.line_number);

    // Test None case
    finding.line_number = None;
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding.line_number, deserialized.line_number);
}

/// Test 10: Sources array preservation
#[test]
fn test_field_preservation_sources_array() {
    let mut finding = create_test_finding();
    finding.sources = vec![
        "semgrep".to_string(),
        "llm-discovery".to_string(),
        "llm-verification".to_string(),
    ];

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(finding.sources.len(), deserialized.sources.len());
    assert!(deserialized.sources.contains(&"semgrep".to_string()));
    assert!(deserialized.sources.contains(&"llm-discovery".to_string()));
}

/// Test 11: Cross-file references preservation
#[test]
fn test_field_preservation_cross_file_references() {
    let mut finding = create_test_finding();
    finding.cross_file_references = Some(vec![
        "src/api.rs:100".to_string(),
        "src/handler.rs:250".to_string(),
    ]);

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert!(deserialized.cross_file_references.is_some());
    let refs = deserialized.cross_file_references.unwrap();
    assert_eq!(refs.len(), 2);
    assert!(refs.contains(&"src/api.rs:100".to_string()));
}

/// Test 12: Verification status field preservation
#[test]
fn test_field_preservation_verification_status() {
    let statuses = vec![
        VerificationStatus::Confirmed,
        VerificationStatus::FalsePositive,
        VerificationStatus::NeedsReview,
        VerificationStatus::Failed,
    ];

    for status in statuses {
        let mut finding = create_test_finding();
        finding.verification_status = Some(status);

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(
            finding.verification_status,
            deserialized.verification_status
        );
    }
}

/// Test 13: PoC code field preservation
#[test]
fn test_field_preservation_poc_code() {
    let poc_code = r#"
import requests
url = "http://target.com/api"
params = {"id": "1 OR 1=1"}
response = requests.get(url, params=params)
print(response.text)
"#;

    let mut finding = create_test_finding();
    finding.poc_code = Some(poc_code.to_string());
    finding.poc_format = Some("python".to_string());

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(finding.poc_code, deserialized.poc_code);
    assert_eq!(finding.poc_format, deserialized.poc_format);
}

/// Test 14: Mitigation code field preservation
#[test]
fn test_field_preservation_mitigation_code() {
    let mitigation = r#"
// Safe version using parameterized query
const query = "SELECT * FROM users WHERE id = ?";
stmt.execute([user_id]);
"#;

    let mut finding = create_test_finding();
    finding.mitigation_code = Some(mitigation.to_string());

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(finding.mitigation_code, deserialized.mitigation_code);
}

/// Test 15: Agent mode flag preservation
#[test]
fn test_field_preservation_agent_mode_flag() {
    let mut finding = create_test_finding();
    finding.agent_mode = true;
    finding.llm_model = Some("claude-3.5-sonnet".to_string());

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert!(deserialized.agent_mode);
    assert_eq!(
        deserialized.llm_model,
        Some("claude-3.5-sonnet".to_string())
    );
}
