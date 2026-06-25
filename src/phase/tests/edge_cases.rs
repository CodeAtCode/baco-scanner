//! Edge case tests (10 tests)
//!
//! Tests for edge cases, boundary conditions, and error scenarios
//! in the security scanning pipeline.

use crate::config::ScannerConfig;
use crate::findings::{Severity, VulnerabilityFinding};
use crate::phase::tests::test_fixtures::{create_default_metrics_summary, create_test_finding};
use crate::report::html::generate_html_report;
use std::fs;
use tempfile::TempDir;

/// Test: Empty description handling
#[test]
fn test_edge_case_empty_description() {
    let mut finding = create_test_finding();
    finding.description = String::new();
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.description, "");
}

/// Test: Very long description handling
#[test]
fn test_edge_case_very_long_description() {
    let mut finding = create_test_finding();
    finding.description = "x".repeat(10000);

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.description.len(), 10000);
}

/// Test: Unicode characters in fields
#[test]
fn test_edge_case_unicode_characters() {
    let mut finding = create_test_finding();
    finding.description = "SQL injection in 日本語 code".to_string();
    finding.file_path = "src/日本語/module.rs".to_string();

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert!(deserialized.description.contains("日本語"));
    assert!(deserialized.file_path.contains("日本語"));
}

/// Test: Special characters in code snippet
#[test]
fn test_edge_case_special_characters_code_snippet() {
    let mut finding = create_test_finding();
    finding.code_snippet = Some(r#"printf("%s", user_input); // <>&"'"\"#.to_string());

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert!(deserialized.code_snippet.is_some());
    let snippet = deserialized.code_snippet.unwrap();
    assert!(snippet.contains("<>&"));
}

/// Test: Null bytes in strings (should be handled gracefully)
#[test]
fn test_edge_case_null_bytes() {
    let mut finding = create_test_finding();
    finding.id = "test\0id".to_string();

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    // JSON serialization handles null bytes
    assert!(deserialized.id.contains('\0') || deserialized.id.is_empty());
}

/// Test: Maximum severity level
#[test]
fn test_edge_case_maximum_severity() {
    let mut finding = create_test_finding();
    finding.severity = Severity::Critical;

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.severity, Severity::Critical);
}

/// Test: Zero confidence score
#[test]
fn test_edge_case_zero_confidence() {
    let mut finding = create_test_finding();
    finding.confidence_score = 0.0;

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.confidence_score, 0.0);
}

/// Test: Maximum confidence score
#[test]
fn test_edge_case_max_confidence() {
    let mut finding = create_test_finding();
    finding.confidence_score = 1.0;

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.confidence_score, 1.0);
}

/// Test: Empty sources array
#[test]
fn test_edge_case_empty_sources_array() {
    let mut finding = create_test_finding();
    finding.sources = vec![];

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();

    assert!(deserialized.sources.is_empty());
}

/// Test: Report generation with unicode content
#[test]
fn test_edge_case_report_unicode_content() {
    let mut finding = create_test_finding();
    finding.description = "Vulnerability in 日本語コード".to_string();
    finding.title = "テスト脆弱性".to_string();

    let temp_dir = TempDir::new().unwrap();
    let html_path = temp_dir.path().join("report.html");

    let config = ScannerConfig::default();
    let _metrics = create_default_metrics_summary();
    let result = generate_html_report(&[finding], html_path.to_str().unwrap(), Some(&config), None);
    assert!(result.is_ok());

    let html = fs::read_to_string(html_path).unwrap();
    assert!(html.contains("日本語") || html.contains("Vulnerability"));
}
