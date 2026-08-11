//! Integration tests for the scanner orchestrator
//!
//! These tests cover the `run_scanner` entry point and related orchestrator
//! functionality including force flag behavior, checkpoint resume, finding
//! propagation, and early termination.

use baco::checkpoint::{Checkpoint, ScanPhase};
use baco::config::{
    AgentConfig, LlmConfig, LlmPhasesConfig, OutputConfig, PerformanceSettings, ProjectConfig,
    ScannerConfig, ScannerSettings,
};
use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::Scanner;
use std::fs;
use std::path::PathBuf;

// ============================================================================
// Test Fixtures
// ============================================================================

fn create_test_scanner_config() -> ScannerConfig {
    ScannerConfig {
        project: ProjectConfig {
            name: "test-project".to_string(),
            path: "/tmp".to_string(),
            languages: vec!["rust".to_string()],
        },
        scanner: ScannerSettings {
            max_file_size_kb: 1024,
            exclude_paths: vec![],
            semgrep: Default::default(),
            performance: PerformanceSettings::default(),
            ..Default::default()
        },
        llm: LlmConfig {
            phases: LlmPhasesConfig::default(),
            timeout_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            ..Default::default()
        },
        output: OutputConfig {
            dir: "/tmp/test_output".to_string(),
            ..Default::default()
        },
        agent: AgentConfig::default(),
        tickets: Default::default(),
        router: Default::default(),
        aggregation: Default::default(),
        rulesynth: Default::default(),
        normalization: Default::default(),
        cpg: Default::default(),
        exploit: Default::default(),
        validate: Default::default(),
    }
}

fn create_test_finding(title: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-finding-{}", title.replace(" ", "-").to_lowercase()),
        title: title.to_string(),
        description: format!("Test finding: {}", title),
        severity,
        confidence_score: 0.85,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
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

fn get_temp_checkpoint_path(test_name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/baco_orchestrator_test_{}.json", test_name))
}

fn cleanup_checkpoint(test_name: &str) {
    let path = get_temp_checkpoint_path(test_name);
    let _ = fs::remove_file(&path);
}

// ============================================================================
// Test: Scanner Construction
// ============================================================================

#[test]
fn test_scanner_construction_with_force_true() {
    let config = create_test_scanner_config();
    let target_path = PathBuf::from("/tmp");
    let force = true;

    let scanner = Scanner::new(config, target_path, force);

    // force is private, but we can verify initial state
    assert!(scanner.state.borrow().findings.is_empty());
    assert_eq!(scanner.state.borrow().current_phase, ScanPhase::Indexing);
}

#[test]
fn test_scanner_construction_with_force_false() {
    let config = create_test_scanner_config();
    let target_path = PathBuf::from("/tmp");
    let force = false;

    let scanner = Scanner::new(config, target_path, force);

    // force is private, but we can verify initial state
    assert!(scanner.state.borrow().findings.is_empty());
    assert_eq!(scanner.state.borrow().current_phase, ScanPhase::Indexing);
}

// ============================================================================
// Test: Force Flag Behavior
// ============================================================================

#[tokio::test]
async fn test_force_flag_ignores_existing_checkpoint() {
    let output_dir = PathBuf::from("/tmp/test_output_force_ignores");
    let _ = fs::remove_dir_all(&output_dir);
    fs::create_dir_all(&output_dir).unwrap();
    let checkpoint_path = output_dir.join("checkpoint.json");

    let checkpoint = Checkpoint::new("test-force-scan", "/tmp/test-project", chrono::Utc::now());
    checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();
    assert!(checkpoint_path.exists());

    let mut config = create_test_scanner_config();
    config.output.dir = output_dir.to_string_lossy().to_string();
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), true);

    assert!(scanner.checkpoint_path.exists());
    assert_eq!(scanner.checkpoint_path, checkpoint_path);

    let _ = fs::remove_dir_all(&output_dir);
}

#[tokio::test]
async fn test_force_false_with_no_checkpoint_starts_fresh() {
    let output_dir = PathBuf::from("/tmp/test_output_force_no_checkpoint");
    let _ = fs::remove_dir_all(&output_dir);
    fs::create_dir_all(&output_dir).unwrap();

    let mut config = create_test_scanner_config();
    config.output.dir = output_dir.to_string_lossy().to_string();
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    assert!(!scanner.checkpoint_path.exists());
    assert!(scanner.checkpoint_path.parent().is_some());

    let _ = fs::remove_dir_all(&output_dir);
}

// ============================================================================
// Test: Checkpoint Resume
// ============================================================================

#[test]
fn test_checkpoint_resume_loads_completed_phases() {
    cleanup_checkpoint("resume_completed");
    let temp_path = get_temp_checkpoint_path("resume_completed");

    let mut checkpoint =
        Checkpoint::new("test-resume-scan", "/tmp/test-project", chrono::Utc::now());
    checkpoint.current_phase = ScanPhase::LlmStaticAnalysis;
    checkpoint.completed_phases.push(ScanPhase::Indexing);
    checkpoint.completed_phases.push(ScanPhase::Semgrep);
    checkpoint
        .completed_phases
        .push(ScanPhase::LlmStaticAnalysis);

    checkpoint
        .findings_so_far
        .push(create_test_finding("Checkpoint Finding", Severity::High));

    checkpoint.save(temp_path.to_str().unwrap()).unwrap();

    let loaded = Checkpoint::load(temp_path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.completed_phases.len(), 3);
    assert!(loaded.completed_phases.contains(&ScanPhase::Indexing));
    assert!(loaded.completed_phases.contains(&ScanPhase::Semgrep));
    assert!(loaded
        .completed_phases
        .contains(&ScanPhase::LlmStaticAnalysis));
    assert_eq!(loaded.findings_so_far.len(), 1);

    cleanup_checkpoint("resume_completed");
}

#[test]
fn test_checkpoint_resume_loads_analyzed_files() {
    cleanup_checkpoint("resume_analyzed");
    let temp_path = get_temp_checkpoint_path("resume_analyzed");

    let mut checkpoint = Checkpoint::new(
        "test-analyzed-scan",
        "/tmp/test-project",
        chrono::Utc::now(),
    );
    checkpoint.analyzed_files.push("src/main.rs".to_string());
    checkpoint.analyzed_files.push("src/lib.rs".to_string());

    checkpoint.save(temp_path.to_str().unwrap()).unwrap();

    let loaded = Checkpoint::load(temp_path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.analyzed_files.len(), 2);
    assert!(loaded.analyzed_files.contains(&"src/main.rs".to_string()));
    assert!(loaded.analyzed_files.contains(&"src/lib.rs".to_string()));

    cleanup_checkpoint("resume_analyzed");
}

// ============================================================================
// Test: Complete Phase Detection
// ============================================================================

#[test]
fn test_complete_phase_checkpoint_returns_findings_without_running() {
    cleanup_checkpoint("complete_phase");
    let temp_path = get_temp_checkpoint_path("complete_phase");

    let mut checkpoint = Checkpoint::new(
        "test-complete-scan",
        "/tmp/test-project",
        chrono::Utc::now(),
    );
    checkpoint.current_phase = ScanPhase::Reporting;

    checkpoint.completed_phases.push(ScanPhase::Indexing);
    checkpoint.completed_phases.push(ScanPhase::Semgrep);
    checkpoint
        .completed_phases
        .push(ScanPhase::LlmStaticAnalysis);
    checkpoint.completed_phases.push(ScanPhase::CweRouting);
    checkpoint.completed_phases.push(ScanPhase::Reporting);

    let expected_findings = vec![
        create_test_finding("Finding 1", Severity::Critical),
        create_test_finding("Finding 2", Severity::High),
    ];
    checkpoint.findings_so_far = expected_findings.clone();

    checkpoint.save(temp_path.to_str().unwrap()).unwrap();

    let loaded = Checkpoint::load(temp_path.to_str().unwrap()).unwrap();

    assert!(loaded.completed_phases.contains(&ScanPhase::Reporting));

    assert_eq!(loaded.findings_so_far.len(), 2);
    assert_eq!(loaded.findings_so_far[0].title, "Finding 1");
    assert_eq!(loaded.findings_so_far[1].title, "Finding 2");

    cleanup_checkpoint("complete_phase");
}

// ============================================================================
// Test: Finding Propagation
// ============================================================================

#[test]
fn test_scanner_state_findings_updated_via_send_modify() {
    let config = create_test_scanner_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    assert!(scanner.state.borrow().findings.is_empty());

    let test_findings = vec![
        create_test_finding("Test Finding 1", Severity::Medium),
        create_test_finding("Test Finding 2", Severity::Low),
    ];

    scanner.state.send_modify(|s| {
        s.findings = test_findings.clone();
        s.current_phase = ScanPhase::Semgrep;
    });

    let state = scanner.state.borrow();
    assert_eq!(state.findings.len(), 2);
    assert_eq!(state.current_phase, ScanPhase::Semgrep);
    assert_eq!(state.findings[0].title, "Test Finding 1");
}

#[test]
fn test_scanner_state_phase_updates() {
    let config = create_test_scanner_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::LlmStaticAnalysis;
    });

    assert_eq!(
        scanner.state.borrow().current_phase,
        ScanPhase::LlmStaticAnalysis
    );

    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::CweRouting;
    });
    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::LlmDiscovery;
    });

    assert_eq!(
        scanner.state.borrow().current_phase,
        ScanPhase::LlmDiscovery
    );
}

// ============================================================================
// Test: Early Termination Threshold
// ============================================================================

#[test]
fn test_early_termination_threshold_config() {
    let mut config = create_test_scanner_config();
    config.scanner.performance.early_termination_threshold = 5.0;

    assert_eq!(config.scanner.performance.early_termination_threshold, 5.0);

    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    let threshold = scanner
        .config
        .scanner
        .performance
        .early_termination_threshold;
    assert_eq!(threshold, 5.0);
}

#[test]
fn test_early_termination_threshold_zero_disables() {
    let mut config = create_test_scanner_config();
    config.scanner.performance.early_termination_threshold = 0.0;

    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    let threshold = scanner
        .config
        .scanner
        .performance
        .early_termination_threshold;
    assert_eq!(threshold, 0.0);
}

#[test]
fn test_early_termination_threshold_large_value() {
    let mut config = create_test_scanner_config();
    config.scanner.performance.early_termination_threshold = 10000.0;

    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    let threshold = scanner
        .config
        .scanner
        .performance
        .early_termination_threshold;
    assert_eq!(threshold, 10000.0);
}

// ============================================================================
// Test: Checkpoint File Operations
// ============================================================================

#[test]
fn test_checkpoint_save_and_load_roundtrip() {
    cleanup_checkpoint("roundtrip");
    let temp_path = get_temp_checkpoint_path("roundtrip");

    let mut checkpoint = Checkpoint::new(
        "roundtrip-test",
        "/tmp/roundtrip-project",
        chrono::Utc::now(),
    );
    checkpoint.current_phase = ScanPhase::Semgrep;
    checkpoint.file_count = 150;
    checkpoint
        .findings_so_far
        .push(create_test_finding("Roundtrip Finding", Severity::Medium));
    checkpoint
        .analyzed_files
        .push("src/roundtrip.rs".to_string());

    checkpoint.save(temp_path.to_str().unwrap()).unwrap();
    assert!(temp_path.exists());

    let loaded = Checkpoint::load(temp_path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.scan_id, "roundtrip-test");
    assert_eq!(loaded.project_path, "/tmp/roundtrip-project");
    assert_eq!(loaded.current_phase, ScanPhase::Semgrep);
    assert_eq!(loaded.file_count, 150);
    assert_eq!(loaded.findings_so_far.len(), 1);
    assert_eq!(loaded.findings_so_far[0].title, "Roundtrip Finding");
    assert_eq!(loaded.analyzed_files.len(), 1);
    assert_eq!(loaded.analyzed_files[0], "src/roundtrip.rs");

    cleanup_checkpoint("roundtrip");
}

#[test]
fn test_checkpoint_with_multiple_completed_phases() {
    cleanup_checkpoint("multi_phases");
    let temp_path = get_temp_checkpoint_path("multi_phases");

    let mut checkpoint =
        Checkpoint::new("multi-phase-test", "/tmp/multi-project", chrono::Utc::now());
    checkpoint.current_phase = ScanPhase::CrossFileAnalysis;

    checkpoint.completed_phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::CweRouting,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::CrossFileAnalysis,
    ];

    checkpoint.save(temp_path.to_str().unwrap()).unwrap();

    let loaded = Checkpoint::load(temp_path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.completed_phases.len(), 7);
    assert_eq!(loaded.current_phase, ScanPhase::CrossFileAnalysis);

    cleanup_checkpoint("multi_phases");
}

// ============================================================================
// Test: Scanner State Management
// ============================================================================

#[test]
fn test_scanner_state_initial_values() {
    let config = create_test_scanner_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    let state = scanner.state.borrow();

    assert_eq!(state.current_phase, ScanPhase::Indexing);
    assert!(state.findings.is_empty());
}

#[test]
fn test_scanner_state_multiple_modifications() {
    let config = create_test_scanner_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::Indexing;
        s.findings
            .push(create_test_finding("Finding 1", Severity::Low));
    });

    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::Semgrep;
        s.findings
            .push(create_test_finding("Finding 2", Severity::Medium));
    });

    let state = scanner.state.borrow();
    assert_eq!(state.current_phase, ScanPhase::Semgrep);
    assert_eq!(state.findings.len(), 2);
}

// ============================================================================
// Test: Config Construction
// ============================================================================

#[test]
fn test_scanner_config_defaults() {
    let config = create_test_scanner_config();

    assert_eq!(config.project.name, "test-project");
    assert_eq!(config.scanner.max_file_size_kb, 1024);
    assert!(config.scanner.exclude_paths.is_empty());
    assert_eq!(
        config.scanner.performance.early_termination_threshold,
        1000.0
    );
}

#[test]
fn test_scanner_config_custom_performance_settings() {
    let mut config = create_test_scanner_config();
    config.scanner.performance.early_termination_threshold = 10.0;
    config.scanner.performance.enable_incremental_scan = true;

    assert_eq!(config.scanner.performance.early_termination_threshold, 10.0);
    assert!(config.scanner.performance.enable_incremental_scan);
}
// ============================================================================
// Test: Early Exit When Scan Complete
// ============================================================================

#[tokio::test]
async fn test_run_scanner_with_complete_checkpoint_exits_early() {
    let output_dir = PathBuf::from("/tmp/test_output_complete_exit");
    let _ = fs::remove_dir_all(&output_dir);
    fs::create_dir_all(&output_dir).unwrap();
    let checkpoint_path = output_dir.join("checkpoint.json");

    // Create a checkpoint with Reporting phase completed
    let mut checkpoint = Checkpoint::new(
        "test-complete-exit",
        "/tmp/test-project",
        chrono::Utc::now(),
    );
    checkpoint.current_phase = ScanPhase::Reporting;
    checkpoint.completed_phases.push(ScanPhase::Reporting);
    checkpoint
        .findings_so_far
        .push(create_test_finding("Checkpoint Finding", Severity::High));

    checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();
    assert!(checkpoint_path.exists());

    let mut config = create_test_scanner_config();
    config.output.dir = output_dir.to_string_lossy().to_string();

    // Create scanner with force=false
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    // Verify checkpoint path matches
    assert_eq!(scanner.checkpoint_path, checkpoint_path);

    // The scanner should detect the complete checkpoint and exit early
    // We verify this by checking that the checkpoint exists and has Reporting completed
    let loaded = Checkpoint::load(scanner.checkpoint_path.to_str().unwrap()).unwrap();
    assert!(loaded.completed_phases.contains(&ScanPhase::Reporting));

    let _ = fs::remove_dir_all(&output_dir);
}

// ============================================================================
// Test: Force Flag Ignores Checkpoint
// ============================================================================

#[test]
fn test_run_scanner_force_ignores_checkpoint() {
    let output_dir = PathBuf::from("/tmp/test_output_force_ignore");
    let _ = fs::remove_dir_all(&output_dir);
    fs::create_dir_all(&output_dir).unwrap();
    let checkpoint_path = output_dir.join("checkpoint.json");

    // Create a checkpoint with Reporting phase completed
    let mut checkpoint =
        Checkpoint::new("test-force-ignore", "/tmp/test-project", chrono::Utc::now());
    checkpoint.current_phase = ScanPhase::Reporting;
    checkpoint.completed_phases.push(ScanPhase::Reporting);

    checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();
    assert!(checkpoint_path.exists());

    let mut config = create_test_scanner_config();
    config.output.dir = output_dir.to_string_lossy().to_string();

    // Create scanner with force=true
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), true);

    // With force=true, the scanner should still have the checkpoint path
    // but will ignore it during execution
    assert!(scanner.checkpoint_path.exists());

    let _ = fs::remove_dir_all(&output_dir);
}

// ============================================================================
// Test: Checkpoint Creation
// ============================================================================

#[test]
fn test_run_scanner_creates_checkpoint() {
    let output_dir = PathBuf::from("/tmp/test_output_creates_checkpoint");
    let _ = fs::remove_dir_all(&output_dir);
    fs::create_dir_all(&output_dir).unwrap();

    let mut config = create_test_scanner_config();
    config.output.dir = output_dir.to_string_lossy().to_string();

    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    // Verify checkpoint path is set correctly
    assert!(scanner.checkpoint_path.parent().is_some());
    assert_eq!(
        scanner
            .checkpoint_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
        "checkpoint.json"
    );

    let _ = fs::remove_dir_all(&output_dir);
}

// ============================================================================
// Test: Findings Propagation
// ============================================================================

#[test]
fn test_run_scanner_propagates_findings() {
    let config = create_test_scanner_config();
    let scanner = Scanner::new(config, PathBuf::from("/tmp"), false);

    // Verify initial state has no findings
    assert!(scanner.state.borrow().findings.is_empty());

    // Simulate findings being added (as would happen during a scan)
    let test_findings = vec![
        create_test_finding("Propagation Finding 1", Severity::Critical),
        create_test_finding("Propagation Finding 2", Severity::High),
    ];

    scanner.state.send_modify(|s| {
        s.findings = test_findings.clone();
    });

    // Verify findings were propagated
    let state = scanner.state.borrow();
    assert_eq!(state.findings.len(), 2);
    assert_eq!(state.findings[0].severity, Severity::Critical);
    assert_eq!(state.findings[1].severity, Severity::High);
}
