//! Unit tests for scanner/parallel.rs - parallel phase execution utilities
//!
//! Tests cover ParallelPhaseConfig, ParallelPhaseResult, phase execution functions,
//! and the combine_parallel_results function for parallel phase orchestration.

use baco::checkpoint::ScanPhase;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::{
    combine_parallel_results, has_valid_checkpoint_findings, run_indexing_phase,
    run_llm_static_phase, run_semgrep_phase, ParallelPhaseConfig, ParallelPhaseResult, Scanner,
};
use indicatif::ProgressBar;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Test Fixtures
// ============================================================================

fn create_test_finding(title: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        severity,
        confidence_score: 0.8,
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("let x = 5;".to_string()),
        description: format!("Test vulnerability: {}", title),
        cwe_id: Some("CWE-79".to_string()),
        verification_status: None,
        sources: vec!["test".to_string()],
        cross_file_references: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
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

fn create_test_config() -> baco::config::ScannerConfig {
    use baco::config::{AgentConfig, LlmPhasesConfig, PerformanceSettings, ScannerSettings};

    baco::config::ScannerConfig {
        project: baco::config::ProjectConfig {
            languages: vec!["rust".to_string()],
            ..Default::default()
        },
        scanner: ScannerSettings {
            max_file_size_kb: 1024,
            exclude_paths: vec![],
            semgrep: baco::config::SemgrepSettings::default(),
            performance: PerformanceSettings::default(),
            ..Default::default()
        },
        llm: baco::config::LlmConfig {
            phases: LlmPhasesConfig::default(),
            timeout_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            ..Default::default()
        },
        output: baco::config::OutputConfig {
            dir: "/tmp/test_output".to_string(),
            ..Default::default()
        },
        agent: AgentConfig::default(),
        tickets: baco::config::TicketConfig { systems: vec![] },
        router: baco::config::RouterConfig::default(),
        aggregation: baco::config::AggregationConfig::default(),
        rulesynth: baco::config::RuleSynthConfig::default(),
        normalization: baco::config::NormalizationConfig::default(),
        cpg: baco::config::CpgConfig::default(),
        exploit: baco::config::ExploitConfig::default(),
    }
}

// ============================================================================
// ParallelPhaseConfig Tests
// ============================================================================

#[test]
fn test_parallel_phase_config_all_enabled() {
    let pb = ProgressBar::hidden();
    let completed_phases: [ScanPhase; 2] = [ScanPhase::Indexing, ScanPhase::Semgrep];

    let config = ParallelPhaseConfig {
        indexing_enabled: true,
        semgrep_enabled: true,
        llm_static_enabled: true,
        completed_phases: &completed_phases,
        progress_bar: &pb,
    };

    assert!(config.indexing_enabled);
    assert!(config.semgrep_enabled);
    assert!(config.llm_static_enabled);
    assert_eq!(config.completed_phases.len(), 2);
}

#[test]
fn test_parallel_phase_config_all_disabled() {
    let pb = ProgressBar::hidden();
    let completed_phases: [ScanPhase; 0] = [];

    let config = ParallelPhaseConfig {
        indexing_enabled: false,
        semgrep_enabled: false,
        llm_static_enabled: false,
        completed_phases: &completed_phases,
        progress_bar: &pb,
    };

    assert!(!config.indexing_enabled);
    assert!(!config.semgrep_enabled);
    assert!(!config.llm_static_enabled);
    assert!(config.completed_phases.is_empty());
}

#[test]
fn test_parallel_phase_config_partial_enabled() {
    let pb = ProgressBar::hidden();
    let completed_phases: [ScanPhase; 1] = [ScanPhase::Indexing];

    let config = ParallelPhaseConfig {
        indexing_enabled: true,
        semgrep_enabled: false,
        llm_static_enabled: true,
        completed_phases: &completed_phases,
        progress_bar: &pb,
    };

    assert!(config.indexing_enabled);
    assert!(!config.semgrep_enabled);
    assert!(config.llm_static_enabled);
    assert_eq!(config.completed_phases.len(), 1);
}

#[test]
fn test_parallel_phase_config_empty_completed_phases() {
    let pb = ProgressBar::hidden();
    let completed_phases: [ScanPhase; 0] = [];

    let config = ParallelPhaseConfig {
        indexing_enabled: true,
        semgrep_enabled: true,
        llm_static_enabled: true,
        completed_phases: &completed_phases,
        progress_bar: &pb,
    };

    assert!(config.completed_phases.is_empty());
    assert_eq!(config.completed_phases.len(), 0);
}

// ============================================================================
// ParallelPhaseResult Tests
// ============================================================================

#[test]
fn test_parallel_phase_result_all_findings() {
    let indexing_findings = vec![create_test_finding("Indexing", Severity::Medium)];
    let semgrep_findings = vec![create_test_finding("Semgrep", Severity::High)];
    let llm_findings = vec![create_test_finding("LLM", Severity::Critical)];
    let analyzed_files = vec!["file1.rs".to_string(), "file2.rs".to_string()];
    let duration = Duration::from_secs(42);

    let result = ParallelPhaseResult {
        indexing_findings: indexing_findings.clone(),
        semgrep_findings: semgrep_findings.clone(),
        llm_static_findings: llm_findings.clone(),
        analyzed_files: analyzed_files.clone(),
        duration,
    };

    assert_eq!(result.indexing_findings.len(), 1);
    assert_eq!(result.semgrep_findings.len(), 1);
    assert_eq!(result.llm_static_findings.len(), 1);
    assert_eq!(result.analyzed_files.len(), 2);
    assert_eq!(result.duration.as_secs(), 42);
}

#[test]
fn test_parallel_phase_result_empty_findings() {
    let duration = Duration::from_secs(0);

    let result = ParallelPhaseResult {
        indexing_findings: vec![],
        semgrep_findings: vec![],
        llm_static_findings: vec![],
        analyzed_files: vec![],
        duration,
    };

    assert!(result.indexing_findings.is_empty());
    assert!(result.semgrep_findings.is_empty());
    assert!(result.llm_static_findings.is_empty());
    assert!(result.analyzed_files.is_empty());
    assert_eq!(result.duration.as_secs(), 0);
}

#[test]
fn test_parallel_phase_result_only_indexing() {
    let indexing_findings = vec![create_test_finding("Indexing", Severity::Low)];
    let duration = Duration::from_millis(500);

    let result = ParallelPhaseResult {
        indexing_findings,
        semgrep_findings: vec![],
        llm_static_findings: vec![],
        analyzed_files: vec![],
        duration,
    };

    assert_eq!(result.indexing_findings.len(), 1);
    assert!(result.semgrep_findings.is_empty());
    assert!(result.llm_static_findings.is_empty());
}

#[test]
fn test_parallel_phase_result_mixed_severities() {
    let indexing_findings = vec![
        create_test_finding("Low", Severity::Low),
        create_test_finding("Medium", Severity::Medium),
    ];
    let semgrep_findings = vec![create_test_finding("High", Severity::High)];
    let llm_findings = vec![create_test_finding("Critical", Severity::Critical)];
    let duration = Duration::from_secs(120);

    let result = ParallelPhaseResult {
        indexing_findings,
        semgrep_findings,
        llm_static_findings: llm_findings,
        analyzed_files: vec!["test.rs".to_string()],
        duration,
    };

    assert_eq!(result.indexing_findings.len(), 2);
    assert_eq!(result.semgrep_findings.len(), 1);
    assert_eq!(result.llm_static_findings.len(), 1);
    assert_eq!(result.duration.as_secs(), 120);
}

// ============================================================================
// combine_parallel_results Tests
// ============================================================================

#[test]
fn test_combine_parallel_results_all_success() {
    let initial_findings = vec![create_test_finding("Initial", Severity::Low)];

    let indexing_result = Ok((
        vec![create_test_finding("Indexing", Severity::Medium)],
        vec!["file1.rs".to_string()],
    ));

    let semgrep_result = Ok((
        vec![create_test_finding("Semgrep", Severity::High)],
        vec!["file2.rs".to_string()],
    ));

    let llm_static_result = Ok((
        vec![create_test_finding("LLM", Severity::Critical)],
        vec!["file3.rs".to_string()],
    ));

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 4);
    assert_eq!(analyzed_files.len(), 1);
    assert_eq!(analyzed_files[0], "file3.rs");
}

#[test]
fn test_combine_parallel_results_all_none() {
    let initial_findings = vec![create_test_finding("Initial", Severity::Low)];

    let (combined_findings, analyzed_files) =
        combine_parallel_results(initial_findings.clone(), None, None, None);

    assert_eq!(combined_findings.len(), 1);
    assert_eq!(combined_findings[0].title, "Initial");
    assert!(analyzed_files.is_empty());
}

#[test]
fn test_combine_parallel_results_all_errors() {
    let initial_findings = vec![create_test_finding("Initial", Severity::Low)];

    let indexing_result = Err("Indexing failed".to_string());
    let semgrep_result = Err("Semgrep failed".to_string());
    let llm_static_result = Err("LLM failed".to_string());

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 1);
    assert!(analyzed_files.is_empty());
}

#[test]
fn test_combine_parallel_results_partial_success_indexing_only() {
    let initial_findings = vec![create_test_finding("Initial", Severity::Low)];

    let indexing_result = Ok((
        vec![create_test_finding("Indexing", Severity::Medium)],
        vec!["file1.rs".to_string()],
    ));

    let semgrep_result = Err("Semgrep failed".to_string());
    let llm_static_result = Err("LLM failed".to_string());

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 2);
    assert!(analyzed_files.is_empty());
}

#[test]
fn test_combine_parallel_results_partial_success_llm_only() {
    let initial_findings = vec![create_test_finding("Initial", Severity::Low)];

    let indexing_result = Err("Indexing failed".to_string());
    let semgrep_result = Err("Semgrep failed".to_string());
    let llm_static_result = Ok((
        vec![create_test_finding("LLM", Severity::Critical)],
        vec!["file3.rs".to_string()],
    ));

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 2);
    assert_eq!(analyzed_files.len(), 1);
    assert_eq!(analyzed_files[0], "file3.rs");
}

#[test]
fn test_combine_parallel_results_indexing_and_semgrep_success() {
    let initial_findings = vec![create_test_finding("Initial", Severity::Low)];

    let indexing_result = Ok((
        vec![create_test_finding("Indexing", Severity::Medium)],
        vec!["file1.rs".to_string()],
    ));

    let semgrep_result = Ok((
        vec![create_test_finding("Semgrep", Severity::High)],
        vec!["file2.rs".to_string()],
    ));

    let llm_static_result = Err("LLM failed".to_string());

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 3);
    assert!(analyzed_files.is_empty());
}

#[test]
fn test_combine_parallel_results_empty_initial_findings() {
    let initial_findings: Vec<VulnerabilityFinding> = vec![];

    let indexing_result = Ok((
        vec![create_test_finding("Indexing", Severity::Medium)],
        vec!["file1.rs".to_string()],
    ));

    let semgrep_result = Ok((
        vec![create_test_finding("Semgrep", Severity::High)],
        vec!["file2.rs".to_string()],
    ));

    let llm_static_result = Ok((
        vec![create_test_finding("LLM", Severity::Critical)],
        vec!["file3.rs".to_string()],
    ));

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 3);
    assert_eq!(analyzed_files.len(), 1);
}

#[test]
fn test_combine_parallel_results_empty_phase_findings() {
    let initial_findings = vec![create_test_finding("Initial", Severity::Low)];

    let indexing_result = Ok((vec![], vec!["file1.rs".to_string()]));
    let semgrep_result = Ok((vec![], vec!["file2.rs".to_string()]));
    let llm_static_result = Ok((vec![], vec!["file3.rs".to_string()]));

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 1);
    assert_eq!(analyzed_files.len(), 1);
    assert_eq!(analyzed_files[0], "file3.rs");
}

#[test]
fn test_combine_parallel_results_only_initial_and_llm() {
    let initial_findings = vec![
        create_test_finding("Initial1", Severity::Low),
        create_test_finding("Initial2", Severity::Medium),
    ];

    let indexing_result = Err("Indexing failed".to_string());
    let semgrep_result = Err("Semgrep failed".to_string());
    let llm_static_result = Ok((
        vec![
            create_test_finding("LLM1", Severity::High),
            create_test_finding("LLM2", Severity::Critical),
        ],
        vec!["file3.rs".to_string(), "file4.rs".to_string()],
    ));

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 4);
    assert_eq!(analyzed_files.len(), 2);
}

// ============================================================================
// Phase Execution Function Tests (Mock/Integration)
// ============================================================================

#[tokio::test]
async fn test_run_indexing_phase_with_empty_findings() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);
    let pb = ProgressBar::hidden();

    let result = run_indexing_phase(&scanner, &pb, vec![]).await;

    assert!(result.is_ok());
    let (findings, analyzed_files) = result.unwrap();
    assert!(findings.is_empty());
    assert!(analyzed_files.is_empty());
}

#[tokio::test]
async fn test_run_semgrep_phase_with_empty_findings() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);
    let pb = ProgressBar::hidden();

    let result = run_semgrep_phase(&scanner, &pb, vec![]).await;

    assert!(result.is_ok());
    let (findings, analyzed_files) = result.unwrap();
    assert!(findings.is_empty());
    assert!(analyzed_files.is_empty());
}

#[tokio::test]
async fn test_run_llm_static_phase_with_empty_findings() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);
    let pb = ProgressBar::hidden();

    let result = run_llm_static_phase(&scanner, &pb, vec![], &[]).await;

    assert!(result.is_ok());
    let (findings, analyzed_files) = result.unwrap();
    assert!(findings.is_empty());
    assert!(analyzed_files.is_empty());
}

#[tokio::test]
async fn test_run_indexing_phase_with_initial_findings() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);
    let pb = ProgressBar::hidden();

    let initial_findings = vec![create_test_finding("Initial", Severity::High)];

    let result = run_indexing_phase(&scanner, &pb, initial_findings).await;

    assert!(result.is_ok());
    let (findings, _) = result.unwrap();
    assert!(!findings.is_empty());
}

#[tokio::test]
async fn test_run_semgrep_phase_with_initial_findings() {
    let config = create_test_config();
    let target_path = PathBuf::from("/tmp/test-project");
    let scanner = Scanner::new(config, target_path, false);
    let pb = ProgressBar::hidden();

    let initial_findings = vec![create_test_finding("Initial", Severity::Medium)];

    let result = run_semgrep_phase(&scanner, &pb, initial_findings).await;

    assert!(result.is_ok());
    let (findings, _) = result.unwrap();
    assert!(!findings.is_empty());
}

// ============================================================================
// has_valid_checkpoint_findings Tests
// ============================================================================

#[tokio::test]
async fn test_has_valid_checkpoint_findings_nonexistent_path() {
    let temp_path = PathBuf::from("/tmp/nonexistent_checkpoint_12345");
    let phase = ScanPhase::Indexing;

    let result = has_valid_checkpoint_findings(&temp_path, &phase).await;

    assert!(!result);
}

#[tokio::test]
async fn test_has_valid_checkpoint_findings_different_phases() {
    let temp_path = PathBuf::from("/tmp/nonexistent_checkpoint_12345");

    let indexing_result = has_valid_checkpoint_findings(&temp_path, &ScanPhase::Indexing).await;
    let semgrep_result = has_valid_checkpoint_findings(&temp_path, &ScanPhase::Semgrep).await;
    let llm_result = has_valid_checkpoint_findings(&temp_path, &ScanPhase::LlmStaticAnalysis).await;

    assert!(!indexing_result);
    assert!(!semgrep_result);
    assert!(!llm_result);
}

// ============================================================================
// Edge Cases and Integration Tests
// ============================================================================

#[test]
fn test_parallel_phase_config_with_single_completed_phase() {
    let pb = ProgressBar::hidden();
    let completed_phases: [ScanPhase; 1] = [ScanPhase::Complete];

    let config = ParallelPhaseConfig {
        indexing_enabled: false,
        semgrep_enabled: false,
        llm_static_enabled: false,
        completed_phases: &completed_phases,
        progress_bar: &pb,
    };

    assert_eq!(config.completed_phases.len(), 1);
    assert_eq!(config.completed_phases[0], ScanPhase::Complete);
}

#[test]
fn test_combine_results_with_many_findings() {
    let initial_findings: Vec<VulnerabilityFinding> = (0..10)
        .map(|i| create_test_finding(&format!("Initial{}", i), Severity::Low))
        .collect();

    let indexing_result = Ok((
        vec![create_test_finding("Indexing", Severity::Medium)],
        vec!["file1.rs".to_string()],
    ));

    let semgrep_result = Ok((
        vec![create_test_finding("Semgrep", Severity::High)],
        vec!["file2.rs".to_string()],
    ));

    let llm_static_result = Ok((
        vec![create_test_finding("LLM", Severity::Critical)],
        vec!["file3.rs".to_string()],
    ));

    let (combined_findings, analyzed_files) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings.len(), 13);
    assert_eq!(analyzed_files.len(), 1);
}

#[test]
fn test_parallel_phase_result_with_zero_duration() {
    let result = ParallelPhaseResult {
        indexing_findings: vec![],
        semgrep_findings: vec![],
        llm_static_findings: vec![],
        analyzed_files: vec![],
        duration: Duration::from_secs(0),
    };

    assert_eq!(result.duration.as_millis(), 0);
    assert!(result.indexing_findings.is_empty());
}

#[test]
fn test_combine_parallel_results_preserves_initial_findings_order() {
    let initial_findings = vec![
        create_test_finding("First", Severity::Low),
        create_test_finding("Second", Severity::Low),
    ];

    let indexing_result = Ok((
        vec![create_test_finding("Indexing", Severity::Medium)],
        vec![],
    ));

    let semgrep_result = Ok((vec![], vec![]));
    let llm_static_result = Ok((vec![], vec![]));

    let (combined_findings, _) = combine_parallel_results(
        initial_findings,
        Some(indexing_result),
        Some(semgrep_result),
        Some(llm_static_result),
    );

    assert_eq!(combined_findings[0].title, "First");
    assert_eq!(combined_findings[1].title, "Second");
    assert_eq!(combined_findings[2].title, "Indexing");
}
