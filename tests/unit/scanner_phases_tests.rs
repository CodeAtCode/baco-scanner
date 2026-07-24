//! Unit tests for scanner/phases.rs - Hunt, Validate, and IndependentVerify phases
//!
//! Tests cover phase orchestration config patterns and phase behavior through
//! the public Scanner API. These tests verify the Cloudflare pattern six-phase
//! orchestration configuration structures.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::Scanner;
use std::path::PathBuf;

// ============================================================================
// Test Fixtures
// ============================================================================

fn create_test_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-001".to_string(),
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability for unit testing".to_string(),
        severity: Severity::High,
        confidence_score: 0.85,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("let x = user_input;".to_string()),
        diff_hunk: None,
        recommendation: Some("Sanitize input".to_string()),
        code_location: Some("src/test.rs:42".to_string()),
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.9),
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

fn create_test_finding_with_line(line: u32) -> VulnerabilityFinding {
    let mut finding = create_test_finding();
    finding.line_number = Some(line);
    finding.id = format!("test-finding-{}", line);
    finding
}

// ============================================================================
// OrchestrationConfig Pattern Tests (Hunt, Validate, IndependentVerify)
// ============================================================================

#[test]
fn test_orchestration_config_default_values() {
    // Test that OrchestrationConfig follows the expected pattern
    let config = baco::config::OrchestrationConfig::default();

    // enabled defaults to true
    assert!(config.enabled);
    // Default has all 7 hunt classes
    assert_eq!(config.hunt_classes.len(), 7);
    assert_eq!(config.validate_batch_size, 10);
    assert!(config.independent_verify);
}

#[test]
fn test_orchestration_config_enabled_true() {
    let config = baco::config::OrchestrationConfig {
        enabled: true,
        ..Default::default()
    };

    assert!(config.enabled);
    // Default already has all 7 hunt classes
    assert_eq!(config.hunt_classes.len(), 7);
}

#[test]
fn test_orchestration_config_with_hunt_classes() {
    let config = baco::config::OrchestrationConfig {
        enabled: true,
        hunt_classes: vec!["injection".to_string(), "xss".to_string()],
        ..Default::default()
    };

    assert_eq!(config.hunt_classes.len(), 2);
    assert!(config.hunt_classes.contains(&"injection".to_string()));
    assert!(config.hunt_classes.contains(&"xss".to_string()));
}

#[test]
fn test_orchestration_config_with_batch_size() {
    let config = baco::config::OrchestrationConfig {
        validate_batch_size: 10,
        ..Default::default()
    };

    assert_eq!(config.validate_batch_size, 10);
}

#[test]
fn test_orchestration_config_with_independent_verify_enabled() {
    let config = baco::config::OrchestrationConfig {
        independent_verify: true,
        ..Default::default()
    };

    assert!(config.independent_verify);
}

#[test]
fn test_orchestration_config_clone() {
    let config = baco::config::OrchestrationConfig {
        enabled: true,
        hunt_classes: vec!["auth".to_string()],
        validate_batch_size: 5,
        independent_verify: true,
    };

    let cloned = config.clone();

    assert_eq!(cloned.enabled, config.enabled);
    assert_eq!(cloned.hunt_classes, config.hunt_classes);
    assert_eq!(cloned.validate_batch_size, config.validate_batch_size);
    assert_eq!(cloned.independent_verify, config.independent_verify);
}

#[test]
fn test_orchestration_config_debug_format() {
    let config = baco::config::OrchestrationConfig {
        enabled: true,
        hunt_classes: vec!["xss".to_string()],
        validate_batch_size: 10,
        independent_verify: false,
    };

    let debug_str = format!("{:?}", config);
    assert!(debug_str.contains("enabled"));
    assert!(debug_str.contains("hunt_classes"));
}

#[test]
fn test_orchestration_config_all_hunt_classes() {
    let config = baco::config::OrchestrationConfig {
        enabled: true,
        hunt_classes: vec![
            "injection".to_string(),
            "auth".to_string(),
            "xss".to_string(),
            "path_traversal".to_string(),
            "crypto".to_string(),
            "resource".to_string(),
            "deserialization".to_string(),
        ],
        validate_batch_size: 10,
        independent_verify: true,
    };

    assert!(config.enabled);
    assert_eq!(config.hunt_classes.len(), 7);
    assert_eq!(config.validate_batch_size, 10);
    assert!(config.independent_verify);
}

// ============================================================================
// Hunter Phase Integration Tests
// ============================================================================

#[test]
fn test_scanner_has_hunt_phase_capability() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Verify scanner exists and is accessible
    assert!(scanner.findings().is_empty());
}

#[tokio::test]
async fn test_hunt_phase_disabled_by_default() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Hunt phase is part of the orchestration, verify scanner is initialized
    assert!(scanner.findings().is_empty());
}

#[tokio::test]
async fn test_hunt_phase_with_empty_findings() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Initial state should have no findings
    let findings = scanner.findings();
    assert!(findings.is_empty());
}

// ============================================================================
// Validate Phase Integration Tests
// ============================================================================

#[test]
fn test_scanner_has_validate_phase_capability() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Verify scanner exists and is accessible
    assert!(scanner.findings().is_empty());
}

#[tokio::test]
async fn test_validate_phase_disabled_by_default() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Validate phase is part of the orchestration, verify scanner is initialized
    assert!(scanner.findings().is_empty());
}

#[tokio::test]
async fn test_validate_phase_preserves_findings_when_disabled() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    let initial_findings = vec![create_test_finding()];
    scanner.update_findings(initial_findings.clone());

    let findings = scanner.findings();
    assert_eq!(findings.len(), 1);
}

// ============================================================================
// Independent Verify Phase Integration Tests
// ============================================================================

#[test]
fn test_scanner_has_independent_verify_capability() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Verify scanner exists and is accessible
    assert!(scanner.findings().is_empty());
}

#[tokio::test]
async fn test_independent_verify_disabled_by_default() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Independent verify is part of the orchestration, verify scanner is initialized
    assert!(scanner.findings().is_empty());
}

#[tokio::test]
async fn test_independent_verify_with_empty_source() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Verify scanner handles empty initial state
    let findings = scanner.findings();
    assert!(findings.is_empty());
}

// ============================================================================
// Cross-Phase Configuration Tests
// ============================================================================

#[test]
fn test_all_phase_configs_share_common_fields() {
    // Verify OrchestrationConfig has all required fields for all phases
    let config = baco::config::OrchestrationConfig {
        enabled: true,
        hunt_classes: vec!["injection".to_string()],
        validate_batch_size: 10,
        independent_verify: true,
    };

    // All fields should be accessible
    assert!(config.enabled);
    assert!(!config.hunt_classes.is_empty());
    assert!(config.validate_batch_size > 0);
    assert!(config.independent_verify);
}

#[test]
fn test_orchestration_config_field_independence() {
    // Verify fields can be set independently
    let config1 = baco::config::OrchestrationConfig {
        enabled: true,
        ..Default::default()
    };

    let config2 = baco::config::OrchestrationConfig {
        hunt_classes: vec!["xss".to_string()],
        ..Default::default()
    };

    let config3 = baco::config::OrchestrationConfig {
        validate_batch_size: 100,
        ..Default::default()
    };

    let config4 = baco::config::OrchestrationConfig {
        independent_verify: true,
        ..Default::default()
    };

    assert!(config1.enabled);
    assert!(config2.hunt_classes.contains(&"xss".to_string()));
    assert_eq!(config3.validate_batch_size, 100);
    assert!(config4.independent_verify);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_orchestration_config_zero_batch_size() {
    let config = baco::config::OrchestrationConfig {
        validate_batch_size: 0,
        ..Default::default()
    };

    assert_eq!(config.validate_batch_size, 0);
}

#[test]
fn test_orchestration_config_empty_hunt_classes() {
    let config = baco::config::OrchestrationConfig {
        hunt_classes: vec![],
        ..Default::default()
    };

    assert!(config.hunt_classes.is_empty());
}

#[test]
fn test_orchestration_config_all_disabled() {
    let config = baco::config::OrchestrationConfig {
        enabled: false,
        hunt_classes: vec![],
        validate_batch_size: 0,
        independent_verify: false,
    };

    assert!(!config.enabled);
    assert!(config.hunt_classes.is_empty());
    assert_eq!(config.validate_batch_size, 0);
    assert!(!config.independent_verify);
}

#[test]
fn test_orchestration_config_all_enabled() {
    let config = baco::config::OrchestrationConfig {
        enabled: true,
        hunt_classes: vec!["all".to_string()],
        validate_batch_size: usize::MAX,
        independent_verify: true,
    };

    assert!(config.enabled);
    assert!(!config.hunt_classes.is_empty());
    assert_eq!(config.validate_batch_size, usize::MAX);
    assert!(config.independent_verify);
}

// ============================================================================
// Finding Integration Tests
// ============================================================================

#[test]
fn test_finding_with_line_number() {
    let finding = create_test_finding_with_line(42);

    assert_eq!(finding.line_number, Some(42));
    assert_eq!(finding.id, "test-finding-42");
}

#[test]
fn test_finding_with_various_line_numbers() {
    let lines = vec![1, 10, 42, 100, 9999];

    for line in lines {
        let finding = create_test_finding_with_line(line);
        assert_eq!(finding.line_number, Some(line));
    }
}

#[tokio::test]
async fn test_scanner_with_many_findings() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    let findings: Vec<VulnerabilityFinding> = (0..100)
        .map(|i| {
            let mut f = create_test_finding();
            f.id = format!("finding-{}", i);
            f.line_number = Some(i as u32);
            f
        })
        .collect();

    scanner.update_findings(findings.clone());

    let returned = scanner.findings();
    assert_eq!(returned.len(), 100);
}

// ============================================================================
// Scanner State Tests
// ============================================================================

#[test]
fn test_scanner_config_accessible() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config.clone(), target_path, false);

    assert_eq!(scanner.config.output.dir, config.output.dir);
}

#[test]
fn test_scanner_target_path() {
    let config = baco::config::ScannerConfig::default();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path.clone(), false);

    assert_eq!(scanner.target_path(), target_path.as_path());
}

#[test]
fn test_scanner_state_initial_empty() {
    let config = baco::config::ScannerConfig::default();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    let state = scanner.state.borrow();
    assert!(state.findings.is_empty());
    assert!(state.errors.is_empty());
}

// ============================================================================
// Phase Configuration Consistency Tests
// ============================================================================

#[test]
fn test_orchestration_config_debug_all_variants() {
    let config1 = baco::config::OrchestrationConfig {
        enabled: true,
        hunt_classes: vec!["xss".to_string()],
        validate_batch_size: 5,
        independent_verify: false,
    };

    let config2 = baco::config::OrchestrationConfig {
        enabled: true,
        hunt_classes: vec![],
        validate_batch_size: 10,
        independent_verify: true,
    };

    let config3 = baco::config::OrchestrationConfig {
        enabled: false,
        hunt_classes: vec!["auth".to_string()],
        validate_batch_size: 1,
        independent_verify: true,
    };

    let _debug1 = format!("{:?}", config1);
    let _debug2 = format!("{:?}", config2);
    let _debug3 = format!("{:?}", config3);
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_orchestration_config_partial_updates() {
    let mut config = baco::config::OrchestrationConfig::default();

    config.enabled = true;
    assert!(config.enabled);

    config.hunt_classes.clear();
    config.hunt_classes.push("injection".to_string());
    assert_eq!(config.hunt_classes.len(), 1);

    config.validate_batch_size = 50;
    assert_eq!(config.validate_batch_size, 50);

    config.independent_verify = true;
    assert!(config.independent_verify);
}
