//! Unit tests for scanner/core.rs
//!
//! Tests cover Scanner initialization, configuration, core methods,
//! and utility functions like URL parsing.

use baco::checkpoint::ScanPhase;
use baco::config::{
    LlmConfig, LlmPhasesConfig, OutputConfig, PerformanceSettings, ScannerSettings,
};
use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::Scanner;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// Test Fixtures
// ============================================================================

fn create_test_config() -> baco::config::ScannerConfig {
    baco::config::ScannerConfig {
        output: OutputConfig {
            dir: "/tmp/baco_test_output".to_string(),
            format: vec!["json".to_string()],
        },
        scanner: ScannerSettings {
            performance: PerformanceSettings {
                early_termination_threshold: 100.0,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

fn create_test_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-001".to_string(),
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability for unit testing".to_string(),
        severity: Severity::High,
        confidence_score: 0.85,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.c".to_string(),
        line_number: Some(42),
        code_snippet: Some("printf(user_input)".to_string()),
        diff_hunk: None,
        recommendation: Some("Use sanitized input".to_string()),
        code_location: Some("src/test.c:42".to_string()),
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
    }
}

// ============================================================================
// Scanner::new() Tests
// ============================================================================

#[test]
fn test_scanner_new_creates_valid_instance() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config.clone(), target_path.clone(), false);

    assert_eq!(scanner.config.output.dir, config.output.dir);
    assert_eq!(scanner.target_path, target_path);
    assert!(scanner.findings().is_empty());
}

#[test]
fn test_scanner_new_with_force_flag() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let _scanner = Scanner::new(config, target_path, true);

    // Force flag is internal state, just verify scanner was created
}

#[test]
fn test_scanner_new_sets_checkpoint_path() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    assert!(scanner.checkpoint_path.ends_with("checkpoint.json"));
}

// ============================================================================
// Scanner::with_initial_findings() Tests
// ============================================================================

#[test]
fn test_scanner_with_initial_findings() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let initial_findings = vec![create_test_finding(), create_test_finding()];

    let scanner =
        Scanner::with_initial_findings(config, target_path, initial_findings.clone(), false);

    let findings = scanner.findings();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].id, "test-finding-001");
}

#[test]
fn test_scanner_with_initial_findings_empty() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");

    let scanner = Scanner::with_initial_findings(config, target_path, Vec::new(), false);

    assert!(scanner.findings().is_empty());
}

// ============================================================================
// Scanner::findings() Tests
// ============================================================================

#[test]
fn test_scanner_findings_returns_clone() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    let findings1 = scanner.findings();
    let findings2 = scanner.findings_mut();

    // Just verify both return the same length
    assert_eq!(findings1.len(), findings2.len());
}

// ============================================================================
// Scanner::update_findings() Tests
// ============================================================================

#[test]
fn test_scanner_update_findings() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    let new_findings = vec![create_test_finding()];
    scanner.update_findings(new_findings.clone());

    let findings = scanner.findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test-finding-001");
}

#[test]
fn test_scanner_update_findings_replaces_all() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Add initial findings
    scanner.update_findings(vec![create_test_finding(), create_test_finding()]);
    assert_eq!(scanner.findings().len(), 2);

    // Replace with different findings
    let mut new_finding = create_test_finding();
    new_finding.id = "new-finding-002".to_string();
    scanner.update_findings(vec![new_finding]);

    let findings = scanner.findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "new-finding-002");
}

// ============================================================================
// Scanner::add_finding() Tests
// ============================================================================

#[test]
fn test_scanner_add_finding() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    let finding = create_test_finding();
    scanner.add_finding(finding);

    let findings = scanner.findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test-finding-001");
}

#[test]
fn test_scanner_add_finding_multiple() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    scanner.add_finding(create_test_finding());
    scanner.add_finding(create_test_finding());
    scanner.add_finding(create_test_finding());

    let findings = scanner.findings();
    assert_eq!(findings.len(), 3);
}

// ============================================================================
// Scanner::target_path() Tests
// ============================================================================

#[test]
fn test_scanner_target_path() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path.clone(), false);

    assert_eq!(scanner.target_path(), target_path.as_path());
}

#[test]
fn test_scanner_target_path_various_paths() {
    let test_paths = vec![
        "/home/user/project",
        "./relative/path",
        "/tmp/test",
        "/absolute/path/to/project",
    ];

    for path_str in test_paths {
        let config = create_test_config();
        let target_path = PathBuf::from(path_str);
        let scanner = Scanner::new(config, target_path.clone(), false);

        assert_eq!(scanner.target_path(), PathBuf::from(path_str).as_path());
    }
}

// ============================================================================
// Scanner State Tests
// ============================================================================

#[test]
fn test_scanner_state_initial_values() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    let state = scanner.state.borrow();
    assert_eq!(state.current_phase, ScanPhase::Indexing);
    assert_eq!(state.files_scanned, 0);
    assert!(state.findings.is_empty());
    assert!(state.errors.is_empty());
    assert!(state.cve_entries.is_empty());
    assert!(state.project_stack.is_none());
}

#[test]
fn test_scanner_state_updates_with_findings() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    scanner.add_finding(create_test_finding());

    let state = scanner.state.borrow();
    assert_eq!(state.findings.len(), 1);
}

// ============================================================================
// Scanner Config Access Tests
// ============================================================================

#[test]
fn test_scanner_config_accessible() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config.clone(), target_path, false);

    assert_eq!(scanner.config.output.dir, config.output.dir);
    assert_eq!(
        scanner
            .config
            .scanner
            .performance
            .early_termination_threshold,
        100.0
    );
}

// ============================================================================
// LLM Metrics Tracker Tests
// ============================================================================

#[test]
fn test_scanner_has_metrics_tracker() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);

    // Verify metrics tracker exists and is accessible
    let _tracker = &scanner.metrics_tracker;
}

// ============================================================================
// URL Parsing Tests - extract_owner_repo_from_url
// ============================================================================

#[test]
fn test_extract_owner_repo_from_url_https() {
    let url = "https://github.com/owner/repo.git";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_https_no_git_suffix() {
    let url = "https://github.com/owner/repo";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_git_ssh() {
    let url = "git@github.com:owner/repo.git";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_git_ssh_no_git_suffix() {
    let url = "git@github.com:owner/repo";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_invalid() {
    let url = "invalid-url";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_none());
}

#[test]
fn test_extract_owner_repo_from_url_empty() {
    let url = "";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_none());
}

#[test]
fn test_extract_owner_repo_from_url_http() {
    let url = "http://gitlab.com/owner/repo.git";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_with_subpath() {
    let url = "https://github.com/owner/repo/subpath";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_whitespace() {
    let url = "  https://github.com/owner/repo.git  ";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

// ============================================================================
// get_git_remote_url Tests (integration with git_analysis)
// ============================================================================

#[test]
fn test_get_git_remote_url_nonexistent_path() {
    let result = Scanner::get_git_remote_url("/nonexistent/path");
    // Should return None for non-existent paths
    assert!(result.is_none());
}

#[test]
fn test_get_git_remote_url_empty_path() {
    let result = Scanner::get_git_remote_url("");
    // Should return None for empty paths
    assert!(result.is_none());
}

// ============================================================================
// Early Termination Threshold Tests
// ============================================================================

#[test]
fn test_scanner_early_termination_config() {
    // Test with high threshold (should not trigger)
    let mut config = create_test_config();
    config.scanner.performance.early_termination_threshold = 1000.0;

    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);
    assert_eq!(
        scanner
            .config
            .scanner
            .performance
            .early_termination_threshold,
        1000.0
    );
}

#[test]
fn test_scanner_early_termination_disabled() {
    // Test with threshold = 0 (disabled)
    let mut config = create_test_config();
    config.scanner.performance.early_termination_threshold = 0.0;

    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);
    assert_eq!(
        scanner
            .config
            .scanner
            .performance
            .early_termination_threshold,
        0.0
    );
}

// ============================================================================
// State Update Tests
// ============================================================================

#[test]
fn test_scanner_state_phase_update() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    // Initial phase should be Indexing
    {
        let state = scanner.state.borrow();
        assert_eq!(state.current_phase, ScanPhase::Indexing);
    }

    // Manually update phase
    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::Semgrep;
    });

    {
        let state = scanner.state.borrow();
        assert_eq!(state.current_phase, ScanPhase::Semgrep);
    }
}

#[test]
fn test_scanner_state_files_scanned_update() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    // Update files_scanned
    scanner.state.send_modify(|s| {
        s.files_scanned = 150;
    });

    let state = scanner.state.borrow();
    assert_eq!(state.files_scanned, 150);
}

#[test]
fn test_scanner_state_errors_update() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    // Add errors
    scanner.state.send_modify(|s| {
        s.errors.push("error 1".to_string());
        s.errors.push("error 2".to_string());
    });

    let state = scanner.state.borrow();
    assert_eq!(state.errors.len(), 2);
    assert_eq!(state.errors[0], "error 1");
}

// ============================================================================
// Multiple Scanner Instances Tests
// ============================================================================

#[test]
fn test_multiple_scanner_instances_independent() {
    let config1 = create_test_config();
    let config2 = create_test_config();

    let scanner1 = Scanner::new(config1, PathBuf::from("/tmp/project1"), false);
    let scanner2 = Scanner::new(config2, PathBuf::from("/tmp/project2"), false);

    scanner1.add_finding(create_test_finding());

    // scanner2 should have no findings
    assert!(scanner2.findings().is_empty());
    assert_eq!(scanner1.findings().len(), 1);
}

// ============================================================================
// Arc<watch::Sender> State Tests
// ============================================================================

#[test]
fn test_scanner_state_arc_clone() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    // Clone the Arc
    let state_clone = scanner.state.clone();

    // Modify through clone
    state_clone.send_modify(|s| {
        s.files_scanned = 100;
    });

    // Verify through original
    let state = scanner.state.borrow();
    assert_eq!(state.files_scanned, 100);
}

#[test]
fn test_scanner_state_watch_channel() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    // Get initial phase
    let initial_phase = scanner.state.borrow().current_phase.clone();

    // Modify
    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::Complete;
    });

    // Verify change
    let new_state = scanner.state.borrow();
    assert_eq!(new_state.current_phase, ScanPhase::Complete);
    assert_ne!(new_state.current_phase, initial_phase);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_scanner_with_root_path() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/"), false);

    assert_eq!(scanner.target_path(), PathBuf::from("/").as_path());
}

#[test]
fn test_scanner_with_current_dir() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("."), false);

    assert_eq!(scanner.target_path(), PathBuf::from(".").as_path());
}

#[test]
fn test_scanner_findings_empty_vector() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    let findings = scanner.findings();
    assert!(findings.is_empty());
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_scanner_update_findings_empty_vector() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    // Add some findings first
    scanner.add_finding(create_test_finding());
    assert_eq!(scanner.findings().len(), 1);

    // Update with empty vector (should clear)
    scanner.update_findings(Vec::new());
    assert!(scanner.findings().is_empty());
}

// ============================================================================
// Integration-style Tests
// ============================================================================

#[test]
fn test_scanner_full_workflow_simulation() {
    let config = create_test_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp/test-project"), false);

    // Simulate finding discovery
    scanner.add_finding(create_test_finding());

    // Simulate state updates
    scanner.state.send_modify(|s| {
        s.files_scanned = 50;
        s.current_phase = ScanPhase::Semgrep;
    });

    // Verify state
    let state = scanner.state.borrow();
    assert_eq!(state.findings.len(), 1);
    assert_eq!(state.files_scanned, 50);
    assert_eq!(state.current_phase, ScanPhase::Semgrep);
}

#[test]
fn test_scanner_with_custom_config_values() {
    let mut config = create_test_config();
    config.output.dir = "/custom/output/dir".to_string();
    config.scanner.performance.early_termination_threshold = 50.0;

    let scanner = Scanner::new(config, PathBuf::from("/tmp/test"), false);

    assert_eq!(scanner.config.output.dir, "/custom/output/dir");
    assert_eq!(
        scanner
            .config
            .scanner
            .performance
            .early_termination_threshold,
        50.0
    );
}

// ============================================================================
// Scanner::run() Tests
// ============================================================================

/// Helper to create a minimal Rust project in a temp directory
fn create_minimal_rust_project(temp_dir: &TempDir) -> std::io::Result<PathBuf> {
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir)?;

    // Create Cargo.toml
    let cargo_toml = r#"[package]
name = "test-project"
version = "0.1.0"
edition = "2021"
"#;
    fs::write(temp_dir.path().join("Cargo.toml"), cargo_toml)?;

    // Create src/main.rs
    let main_rs = r#"fn main() {
    println!("Hello, world!");
}
"#;
    fs::write(src_dir.join("main.rs"), main_rs)?;

    Ok(temp_dir.path().to_path_buf())
}

/// Helper to create a config with LLM phases disabled (no API keys)
fn create_config_without_llm_keys() -> baco::config::ScannerConfig {
    baco::config::ScannerConfig {
        output: OutputConfig {
            dir: "/tmp/baco_run_test_output".to_string(),
            format: vec!["json".to_string()],
        },
        scanner: ScannerSettings {
            performance: PerformanceSettings {
                early_termination_threshold: 100.0,
                ..Default::default()
            },
            ..Default::default()
        },
        llm: LlmConfig {
            phases: LlmPhasesConfig {
                // All phases have no API key, so LLM calls will be skipped
                discovery: Default::default(),
                verification: Default::default(),
                aggregation: Default::default(),
                semgrep: Default::default(),
                ticket_crossref: Default::default(),
                git_analysis: Default::default(),
                cross_file_analysis: Default::default(),
                confidence_scoring: Default::default(),
                ai_aggregation: Default::default(),
                reporting: Default::default(),
                indexing: Default::default(),
                prompt_overrides: Default::default(),
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn test_scanner_run_with_force_flag() {
    // Create a temp directory with a minimal Rust project
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let project_path = create_minimal_rust_project(&temp_dir).expect("Failed to create project");

    // Create scanner with force=true and no LLM API keys
    let config = create_config_without_llm_keys();
    let scanner = Scanner::new(config, project_path, true); // force=true

    // Run the scanner - should complete without panicking
    // LLM phases will be skipped due to missing API keys
    let result = scanner.run().await;

    // Assert result is Ok (even if 0 findings)
    assert!(
        result.is_ok(),
        "Scanner run should succeed even without LLM keys. Got error: {:?}",
        result.err()
    );

    // Verify we got a result (may be empty findings)
    let _findings = result.unwrap();
}

#[tokio::test]
async fn test_scanner_run_empty_project() {
    // Create a temp dir with just a Cargo.toml (no src/)
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create only Cargo.toml
    let cargo_toml = r#"[package]
name = "empty-project"
version = "0.1.0"
edition = "2021"
"#;
    fs::write(temp_dir.path().join("Cargo.toml"), cargo_toml).expect("Failed to write Cargo.toml");

    // Create scanner with force=true and no LLM API keys
    let config = create_config_without_llm_keys();
    let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), true); // force=true

    // Run the scanner - should complete without panicking
    let result = scanner.run().await;

    // Assert result is Ok (even if errors about missing src/)
    assert!(
        result.is_ok(),
        "Scanner run should succeed on empty project. Got error: {:?}",
        result.err()
    );

    let _findings = result.unwrap();
}

/// Test with low early termination threshold - exercises early termination branch after parallel phases
#[tokio::test]
async fn test_scanner_run_with_low_early_termination() {
    // Create a temp directory with a minimal Rust project
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let project_path = create_minimal_rust_project(&temp_dir).expect("Failed to create project");

    // Create config with LOW early_termination_threshold = 1.0
    let mut config = create_config_without_llm_keys();
    config.scanner.performance.early_termination_threshold = 1.0;

    // Create scanner with force=true and no LLM API keys
    let scanner = Scanner::new(config, project_path, true); // force=true

    // Run the scanner - should complete (may trigger early termination)
    let result = scanner.run().await;

    // Assert result is Ok (early termination still returns Ok)
    assert!(
        result.is_ok(),
        "Scanner run should succeed even with low early termination threshold. Got error: {:?}",
        result.err()
    );

    // Verify we got a result (may be empty or have findings)
    let _findings = result.unwrap();
}

/// Test with initial findings and force flag - exercises checkpoint-load skip path
#[tokio::test]
async fn test_scanner_run_with_initial_findings_force() {
    // Create a temp directory with a minimal Rust project
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let project_path = create_minimal_rust_project(&temp_dir).expect("Failed to create project");

    // Create initial findings
    let initial_findings: Vec<VulnerabilityFinding> = (0..3)
        .map(|i| VulnerabilityFinding {
            id: format!("initial-finding-{}", i),
            title: "Initial Test Vulnerability".to_string(),
            description: "A test vulnerability added initially".to_string(),
            severity: Severity::High,
            confidence_score: 0.85,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/test.c".to_string(),
            line_number: Some(42),
            code_snippet: Some("printf(user_input)".to_string()),
            diff_hunk: None,
            recommendation: Some("Use sanitized input".to_string()),
            code_location: Some("src/test.c:42".to_string()),
            already_reported: false,
            sources: vec!["initial".to_string()],
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
        })
        .collect();

    // Create scanner via with_initial_findings with force=true
    let config = create_config_without_llm_keys();
    let scanner = Scanner::with_initial_findings(
        config,
        project_path,
        initial_findings.clone(),
        true, // force=true
    );

    // Verify initial findings are set in scanner state before running
    let pre_run_findings = scanner.findings();
    assert_eq!(
        pre_run_findings.len(),
        3,
        "Scanner should have 3 initial findings before run"
    );

    // Run the scanner
    let result = scanner.run().await;

    // Assert result is Ok
    assert!(
        result.is_ok(),
        "Scanner run should succeed with initial findings. Got error: {:?}",
        result.err()
    );

    // Note: with force=true, run() starts fresh (ignores initial findings)
    // This test verifies the scanner can be created with initial findings and run without panicking
    let _findings = result.unwrap();
}

/// Test with nonexistent target path - just verifies no panic
#[tokio::test]
async fn test_scanner_run_nonexistent_target() {
    // Create scanner with nonexistent target path and force=true
    let config = create_config_without_llm_keys();
    let target_path = PathBuf::from("/nonexistent/path/xyz123");
    let scanner = Scanner::new(config, target_path, true); // force=true

    // Run the scanner - just verify it doesn't panic
    let _ = scanner.run().await;
}
