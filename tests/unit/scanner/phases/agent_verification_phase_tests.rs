//! Unit tests for agent_verification.rs phase logic
//!
//! Tests cover guard branches and helper functions that don't require LLM mocking.

use baco::checkpoint::ScanPhase;
use baco::config;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::metrics::LlmMetricsTracker;
use baco::scanner::Scanner;
use baco::scanner::phases::{PhaseConfig, run_phase};
use indicatif::ProgressBar;
use std::path::PathBuf;
use tempfile::TempDir;

use crate::fixtures::{create_test_config, make_aggregation_finding};

fn create_test_finding(id: &str, severity: Severity) -> VulnerabilityFinding {
    let mut finding = make_aggregation_finding(
        id,
        severity,
        0.9,
        "test.py",
        Some(42),
        Some("CWE-89"),
        Some(VerificationStatus::Confirmed),
    );
    finding.title = "Test Vulnerability".to_string();
    finding.description = "A test vulnerability".to_string();
    finding.code_snippet = Some("execute(user_input)".to_string());
    finding.sources = vec!["test".to_string()];
    finding.priority_score = Some(0.8);
    finding
}

fn create_test_scanner() -> Scanner {
    Scanner::new(config::ScannerConfig::default(), PathBuf::from("."), false)
}

// ============================================================================
// Empty Findings Tests
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_with_empty_findings() {
    // Tests the early loop exit when findings.len() == 0
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings: Vec<VulnerabilityFinding> = vec![];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok(), "Phase should complete with empty findings");
    let (updated, _, _) = result.unwrap();
    assert!(updated.is_empty(), "Empty findings should remain empty");
}

// ============================================================================
// Agent Scaffold Context Tests
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_with_scaffold_disabled() {
    // Tests the code path where agent_scaffold.enabled = false (lines 158-159)
    // This ensures (fn_lookup_opt, call_graph_opt) = (None, None)
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();
    config.agent_scaffold.enabled = false; // Explicitly disabled

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("scaffold-off", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

#[tokio::test]
async fn test_security_agent_verification_with_scaffold_enabled_no_target_fn() {
    // Tests scaffold context building when extract_function_name_from_finding returns None
    // This happens when the finding has no code_snippet and title doesn't match patterns
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();
    config.agent_scaffold.enabled = true;
    config.agent_scaffold.paths_per_target = 10;
    config.agent_scaffold.max_rounds = 5;

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    // Finding with no code_snippet and title that won't match function patterns
    let mut finding = create_test_finding("no-fn-name", Severity::High);
    finding.code_snippet = None;
    finding.title = "General security issue in the system".to_string();
    let findings = vec![finding];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

// ============================================================================
// AgentFlow Disabled Tests
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_with_agentflow_disabled() {
    // Tests the else branch at lines 451-454 where AgentFlow is disabled
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();
    config
        .llm
        .phases
        .security_agent_verification
        .agent_flow
        .enabled = false;

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("agentflow-off", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

// ============================================================================
// Progress Bar Updates Tests
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_progress_updates() {
    // Tests that progress bar updates correctly for multiple findings
    // This exercises lines 162-175 in the findings loop
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    // Create multiple findings to test progress updates
    let findings = vec![
        create_test_finding("progress-1", Severity::Critical),
        create_test_finding("progress-2", Severity::High),
        create_test_finding("progress-3", Severity::Medium),
    ];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

// ============================================================================
// Multiple Findings Processing Tests
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_multiple_findings_same_file() {
    // Tests processing multiple findings from the same file
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    let mut finding1 = create_test_finding("multi-1", Severity::High);
    finding1.file_path = "same_file.py".to_string();
    let mut finding2 = create_test_finding("multi-2", Severity::Critical);
    finding2.file_path = "same_file.py".to_string();
    let mut finding3 = create_test_finding("multi-3", Severity::Low);
    finding3.file_path = "same_file.py".to_string();

    let findings = vec![finding1, finding2, finding3];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

#[tokio::test]
async fn test_security_agent_verification_findings_different_severities() {
    // Tests processing findings with all severity levels
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    let findings = vec![
        create_test_finding("sev-critical", Severity::Critical),
        create_test_finding("sev-high", Severity::High),
        create_test_finding("sev-medium", Severity::Medium),
        create_test_finding("sev-low", Severity::Low),
    ];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

// ============================================================================
// Config Edge Cases
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_with_custom_agent_config() {
    // Tests phase with custom agent configuration
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.agent.max_turns = 10;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("custom-agent", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

#[tokio::test]
async fn test_security_agent_verification_with_max_file_size_config() {
    // Tests phase with custom max_file_size configuration
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.scanner.max_file_size_kb = 1024; // 1MB
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("max-size", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}

// ============================================================================
// Target Path Tests
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_with_temp_target_path() {
    // Tests phase with a real temporary directory as target_path
    let temp_dir = TempDir::new().unwrap();

    // Create a simple Rust file for the function lookup to potentially index
    let test_file = temp_dir.path().join("test.rs");
    std::fs::write(&test_file, "fn test_func() { }\n").unwrap();

    let scanner = Scanner::new(
        config::ScannerConfig::default(),
        temp_dir.path().to_path_buf(),
        false,
    );
    let mut config = create_test_config();
    config.agent.enabled = true;
    config.project.languages = vec!["rust".to_string()];
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());
    config.llm.base_url = "http://localhost:8080".to_string();
    config.llm.phases.security_agent_verification.base_url = "http://localhost:8080".to_string();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = temp_dir.path().to_path_buf();
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("temp-path", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    let (updated, _, _) = result.unwrap();
    assert_eq!(updated.len(), findings.len());
}
