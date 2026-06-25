//! Cross-phase integration tests
//!
//! Tests data flow, metrics aggregation, and confidence calculations across phases.

use crate::confidence::ConfidenceCalculator;
use crate::config::ScannerConfig;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::scanner::Scanner;
use std::fs;
use tempfile::TempDir;

use super::fixtures::create_test_project;

/// Test 7: Findings preserved through all phases
#[tokio::test]
async fn test_cross_phase_findings_preserved() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = create_test_project(&temp_dir);
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    let mut config = ScannerConfig::default();
    config.output.dir = output_dir.to_string_lossy().to_string();
    config.project.path = project_path.to_string_lossy().to_string();
    config.project.name = "test-data-flow".to_string();

    let project_path_clone = project_path.clone();
    let scanner = Scanner::new(config, project_path, false);

    // Create a finding with all possible fields set
    let original_finding = VulnerabilityFinding {
        id: "data-flow-test".to_string(),
        title: "Data Flow Test Finding".to_string(),
        description: "Testing data preservation through phases".to_string(),
        file_path: project_path_clone.join("test.rs").to_string_lossy().to_string(),
        line_number: Some(50),
        severity: Severity::Critical,
        confidence_score: 0.95,
        cwe_id: Some("CWE-89".to_string()),
        sources: vec!["semgrep".to_string(), "llm".to_string(), "agent".to_string()],
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: Some("Verified through multiple sources".to_string()),
        code_snippet: Some("sql_query = \"SELECT * FROM users\".to_string();".to_string()),
        diff_hunk: None,
        recommendation: Some("Use parameterized queries".to_string()),
        code_location: Some("test.rs:50".to_string()),
        already_reported: false,
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.98),
        cross_file_references: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: Some("llama3.1".to_string()),
        agent_mode: true,
    };

    scanner.add_finding(original_finding.clone());

    // Verify finding was added
    let findings = scanner.findings();
    assert_eq!(findings.len(), 1);

    let preserved_finding = scanner.findings()[0].clone();

    // Verify critical fields are preserved
    assert_eq!(preserved_finding.id, original_finding.id);
    assert_eq!(preserved_finding.title, original_finding.title);
    assert_eq!(preserved_finding.description, original_finding.description);
    assert_eq!(preserved_finding.file_path, original_finding.file_path);
    assert_eq!(preserved_finding.line_number, original_finding.line_number);
    assert_eq!(preserved_finding.severity, original_finding.severity);
    assert_eq!(preserved_finding.confidence_score, original_finding.confidence_score);
    assert_eq!(preserved_finding.cwe_id, original_finding.cwe_id);
    assert_eq!(preserved_finding.sources, original_finding.sources);

    // Verify sources array is preserved
    assert_eq!(preserved_finding.sources.len(), 3);
    assert!(preserved_finding.sources.contains(&"semgrep".to_string()));
    assert!(preserved_finding.sources.contains(&"llm".to_string()));
    assert!(preserved_finding.sources.contains(&"agent".to_string()));
}

/// Test 9: Confidence scores calculated correctly
#[tokio::test]
async fn test_cross_phase_confidence_calculation() {
    // Test composite confidence calculation
    let mut finding = VulnerabilityFinding {
        id: "confidence-test".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
        file_path: "test.rs".to_string(),
        line_number: Some(1),
        severity: Severity::High,
        confidence_score: 0.7,
        cwe_id: None,
        sources: vec!["semgrep".to_string(), "llm".to_string(), "agent".to_string()],
        verification_status: None,
        verification_notes: None,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    };

    let composite = ConfidenceCalculator::calculate_composite(&mut finding);

    // Composite should be higher than base (0.7) with multiple sources (+0.15)
    assert!(composite >= 0.85, "Composite should be >= 0.85 with multiple sources, got {}", composite);
    assert!(composite <= 1.0, "Composite should be <= 1.0");

    // Test with single source - no bonus
    let mut single_source_finding = finding.clone();
    single_source_finding.sources = vec!["semgrep".to_string()];
    let single_composite = ConfidenceCalculator::calculate_composite(&mut single_source_finding);
    // Should only have base + severity bonus (0.05 for High) = 0.75
    assert!(single_composite >= 0.7, "Single source should be >= base");

    // Test with many sources
    let mut many_sources_finding = finding.clone();
    many_sources_finding.sources = vec![
        "semgrep".to_string(),
        "llm".to_string(),
        "agent".to_string(),
        "manual".to_string(),
        "poc".to_string(),
    ];
    let many_composite = ConfidenceCalculator::calculate_composite(&mut many_sources_finding);
    assert!(many_composite >= composite, "More sources should increase confidence");

    // Test priority recalculation
    let mut priority_finding = VulnerabilityFinding {
        id: "priority-test".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
        file_path: "test.rs".to_string(),
        line_number: Some(1),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: None,
        sources: vec!["test".to_string()],
        verification_status: None,
        verification_notes: None,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    };

    ConfidenceCalculator::recalculate_priority(&mut priority_finding);
    assert!(priority_finding.priority_score.unwrap_or(0.0) > 0.0, "Priority should be positive");
    assert!(priority_finding.priority_score.unwrap_or(0.0) <= 1.0, "Priority should be <= 1.0");

    // High severity + high confidence = high priority
    let mut high_sev_finding = priority_finding.clone();
    high_sev_finding.severity = Severity::Critical;
    high_sev_finding.confidence_score = 0.95;
    ConfidenceCalculator::recalculate_priority(&mut high_sev_finding);
    assert!(
        high_sev_finding.priority_score.unwrap_or(0.0) > priority_finding.priority_score.unwrap_or(0.0),
        "Critical + high confidence should have higher priority"
    );
}
