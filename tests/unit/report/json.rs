//! Tests for JSON report generation

use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::json::write_findings_json;

fn make_finding(id: &str, severity: Severity, file: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file.to_string(),
        line_number: Some(42),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
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
    }
}

#[test]
fn test_write_findings_json_empty() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_findings_empty.json");

    let result = write_findings_json(&[], output_path.to_str().unwrap(), None);

    assert!(result.is_ok());
    assert!(output_path.exists());

    let content = std::fs::read_to_string(&output_path).unwrap();
    assert_eq!(content, "[]");

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_basic() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_findings_basic.json");

    let findings = vec![
        make_finding("f1", Severity::Critical, "src/critical.rs"),
        make_finding("f2", Severity::High, "src/high.rs"),
    ];

    let result = write_findings_json(&findings, output_path.to_str().unwrap(), None);

    assert!(result.is_ok());
    assert!(output_path.exists());

    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("f1"));
    assert!(content.contains("f2"));
    assert!(content.contains("Critical"));
    assert!(content.contains("High"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_llm_metrics() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_findings_metrics.json");

    let findings = vec![make_finding("f1", Severity::Medium, "src/test.rs")];

    let llm_metrics = baco::llm_metrics::LlmMetrics {
        total_requests: 5,
        total_success: 4,
        total_failed: 1,
        total_cached: 2,
        total_tokens: 2000,
        avg_latency_ms: 150.0,
        by_model: std::collections::HashMap::new(),
        by_operation: std::collections::HashMap::new(),
    };

    let result = write_findings_json(&findings, output_path.to_str().unwrap(), Some(llm_metrics));

    assert!(result.is_ok());
    assert!(output_path.exists());

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_creates_directory() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_subdir").join("test_findings.json");

    let findings = vec![make_finding("f1", Severity::Low, "src/test.rs")];

    let result = write_findings_json(&findings, output_path.to_str().unwrap(), None);

    assert!(result.is_ok());
    assert!(output_path.exists());

    let _ = std::fs::remove_dir_all(temp_dir.join("test_subdir"));
}

#[test]
fn test_findings_serialization() {
    let finding = make_finding("f1", Severity::High, "src/test.rs");

    let json = serde_json::to_string(&finding).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["id"], "f1");
    assert_eq!(parsed["severity"], "High");
    assert_eq!(parsed["file_path"], "src/test.rs");
    assert_eq!(parsed["line_number"], 42);
}
