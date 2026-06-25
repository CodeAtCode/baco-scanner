//! Report generation tests (10 tests)
//!
//! Tests verifying HTML, JSON, and SARIF report generation,
//! including field display, XSS safety, and format compliance.

use crate::config::ScannerConfig;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::phase::tests::test_fixtures::{
    create_complete_finding, create_default_metrics_summary, create_test_finding,
};
use crate::report::html::generate_html_report;
use crate::report::json::write_findings_json;
use crate::report::json::LlmMetricsSummary;
use crate::report::sarif::generate_sarif_report;
use std::fs;
use tempfile::TempDir;

fn create_severity_finding(severity: Severity) -> VulnerabilityFinding {
    let mut finding = create_test_finding();
    finding.severity = severity;
    finding
}

/// Test 42: SARIF format compliance
#[test]
fn test_report_sarif_format_compliance() {
    let findings = vec![create_complete_finding()];

    let result = generate_sarif_report(&findings);
    assert!(result.is_ok());

    let sarif_content = result.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&sarif_content).unwrap();

    // Verify SARIF structure
    assert_eq!(parsed["$schema"].as_str().unwrap(), "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
    assert_eq!(parsed["version"].as_str().unwrap(), "2.1.0");
    assert!(parsed["runs"].is_array());
}

/// Test 44: Report with empty findings
#[test]
fn test_report_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let temp_dir = TempDir::new().unwrap();

    // HTML report
    let html_path = temp_dir.path().join("report.html");
    let config = ScannerConfig::default();
    let _metrics = create_default_metrics_summary();
    let result = generate_html_report(&findings, html_path.to_str().unwrap(), Some(&config), None);
    assert!(result.is_ok());

    // JSON report
    let json_path = temp_dir.path().join("findings.json");
    let result = write_findings_json(&findings, json_path.to_str().unwrap(), None);
    assert!(result.is_ok());

    // SARIF report
    let result = generate_sarif_report(&findings);
    assert!(result.is_ok());
}

/// Test 45: Report with mixed severity findings
#[test]
fn test_report_mixed_severity_findings() {
    let findings = vec![
        create_severity_finding(Severity::Critical),
        create_severity_finding(Severity::High),
        create_severity_finding(Severity::Medium),
        create_severity_finding(Severity::Low),
    ];

    let temp_dir = TempDir::new().unwrap();
    let html_path = temp_dir.path().join("report.html");

    let config = ScannerConfig::default();
    let _metrics = create_default_metrics_summary();
    let result = generate_html_report(&findings, html_path.to_str().unwrap(), Some(&config), None);
    assert!(result.is_ok());

    let html = fs::read_to_string(html_path).unwrap();

    // All severities should be represented
    assert!(html.contains("Critical"));
    assert!(html.contains("High"));
    assert!(html.contains("Medium"));
    assert!(html.contains("Low"));
}

/// Test 46: Report with cross-file references
#[test]
fn test_report_cross_file_references() {
    let mut finding = create_test_finding();
    finding.cross_file_references = Some(vec![
        "src/api.rs:100".to_string(),
        "src/handler.rs:250".to_string(),
    ]);

    let temp_dir = TempDir::new().unwrap();
    let html_path = temp_dir.path().join("report.html");

    let config = ScannerConfig::default();
    let _metrics = create_default_metrics_summary();
    let result = generate_html_report(&[finding], html_path.to_str().unwrap(), Some(&config), None);
    assert!(result.is_ok());
}

/// Test 47: Report with PoC code
#[test]
fn test_report_poc_code_display() {
    let mut finding = create_test_finding();
    finding.poc_code = Some("exploit code here".to_string());
    finding.poc_format = Some("python".to_string());

    let temp_dir = TempDir::new().unwrap();
    let html_path = temp_dir.path().join("report.html");

    let config = ScannerConfig::default();
    let _metrics = create_default_metrics_summary();
    let result = generate_html_report(&[finding], html_path.to_str().unwrap(), Some(&config), None);
    assert!(result.is_ok());

    let html = fs::read_to_string(html_path).unwrap();
    // PoC should be in the report
    assert!(html.contains("exploit code here"));
}

/// Test 48: Report with verification status
#[test]
fn test_report_verification_status_display() {
    let mut finding = create_test_finding();
    finding.verification_status = Some(VerificationStatus::Confirmed);
    finding.verification_notes = Some("Verified by manual review".to_string());

    let temp_dir = TempDir::new().unwrap();
    let html_path = temp_dir.path().join("report.html");

    let config = ScannerConfig::default();
    let _metrics = create_default_metrics_summary();
    let result = generate_html_report(&[finding], html_path.to_str().unwrap(), Some(&config), None);
    assert!(result.is_ok());
}

/// Test 49: Report with LLM metrics
#[test]
fn test_report_llm_metrics_display() {
    let findings = vec![create_test_finding()];
    let temp_dir = TempDir::new().unwrap();
    let html_path = temp_dir.path().join("report.html");

    let config = ScannerConfig::default();
    let metrics = LlmMetricsSummary {
        total_requests: 42,
        successful_requests: 40,
        failed_requests: 2,
        cached_requests: 10,
        total_tokens: 10000,
        avg_latency_ms: 1500.0,
        models: vec![],
        operations: vec![],
    };

    let result = generate_html_report(
        &findings,
        html_path.to_str().unwrap(),
        Some(&config),
        Some(metrics),
    );
    assert!(result.is_ok());
}

/// Test 50: Report XSS safety
#[test]
fn test_report_xss_safety() {
    let mut finding = create_test_finding();
    finding.description = "<script>alert('XSS')</script> SQL Injection".to_string();
    finding.title = "Test <img src=x onerror=alert(1)>".to_string();

    let temp_dir = TempDir::new().unwrap();
    let html_path = temp_dir.path().join("report.html");

    let config = ScannerConfig::default();
    let _metrics = create_default_metrics_summary();
    let result = generate_html_report(&[finding], html_path.to_str().unwrap(), Some(&config), None);
    assert!(result.is_ok());

    let html = fs::read_to_string(html_path).unwrap();

    // Script tags should be escaped
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("&lt;script&gt;") || html.contains("alert('XSS')"));
}
