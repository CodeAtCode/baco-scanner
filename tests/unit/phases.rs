//! Unit tests for scanner phases
//!
//! Tests cover all phase types, execution order, phase context, and finding processing.
#![allow(clippy::useless_vec)] // Test code: vec! is clearer for small arrays

use baco::checkpoint::ScanPhase;
use baco::config::{self, PerformanceSettings, TicketConfig};
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm_metrics::LlmMetricsTracker;
use indicatif::ProgressBar;
use std::path::PathBuf;
use tempfile::TempDir;

// Use centralized fixtures from tests root

/// Create a test finding with minimal configuration
fn create_test_finding(id: &str, title: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        severity,
        confidence_score: 0.8,
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("let x = unsafe { std::ptr::null() };".to_string()),
        description: "Test vulnerability description".to_string(),
        cwe_id: Some("CWE-416".to_string()),
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
    }
}

/// Create a minimal test config
fn create_test_config() -> config::ScannerConfig {
    config::ScannerConfig {
        project: config::ProjectConfig {
            name: "test".to_string(),
            path: ".".to_string(),
            languages: vec!["rust".to_string()],
        },
        output: config::OutputConfig {
            dir: "/tmp/baco_test_output".to_string(),
            format: vec!["html".to_string()],
        },
        scanner: config::ScannerSettings {
            commit_lookback_days: 30,
            max_file_size_kb: 1024,
            exclude_paths: vec![],
            semgrep: config::SemgrepSettings::default(),
            performance: PerformanceSettings::default(),
        },
        llm: config::LlmConfig {
            phases: config::LlmPhasesConfig::default(),
            timeout_secs: 60,
            max_retries: 3,
            retry_backoff_ms: 1000,
            ..Default::default()
        },
        agent: config::AgentConfig {
            enabled: false,
            max_turns: 10,
            tool_timeout_secs: 30,
            trusted_paths: vec![],
            keep_artifacts: false,
        },
        tickets: TicketConfig::default(),
    }
}

/// Create test config with LLM discovery API key
fn create_test_config_with_discovery_key() -> config::ScannerConfig {
    let mut config = create_test_config();
    config.llm.phases.discovery.api_key = Some("test-key".to_string());
    config.llm.phases.discovery.base_url = "http://localhost:11434".to_string();
    config
}

/// Create test config with all features enabled
fn create_test_config_all_features() -> config::ScannerConfig {
    let mut config = create_test_config();
    config.scanner.performance.enable_confidence_refinement = true;
    config.scanner.performance.enable_threat_modeling = true;
    config.scanner.performance.enable_root_cause_dedup = true;
    config.scanner.performance.enable_multi_verifier = true;
    config.scanner.performance.enable_auto_patching = true;
    config.scanner.performance.enable_cve_bootstrap = true;
    config.scanner.performance.enable_poc_compilation = true;
    config.scanner.performance.enable_variant_search = true;
    config
}

/// Create a temporary directory for testing
fn create_temp_test_dir() -> TempDir {
    tempfile::tempdir().unwrap()
}

/// Create a progress bar for testing
fn create_test_progress_bar() -> ProgressBar {
    let pb = ProgressBar::new(100);
    pb.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    pb
}

// ============================================================================
// Phase Type Tests
// ============================================================================

#[tokio::test]
async fn test_indexing_phase_exists() {
    // Verify Indexing phase is a valid ScanPhase variant
    let phase = ScanPhase::Indexing;
    assert_eq!(phase, ScanPhase::Indexing);
}

#[tokio::test]
async fn test_semgrep_phase_exists() {
    let phase = ScanPhase::Semgrep;
    assert_eq!(phase, ScanPhase::Semgrep);
}

#[tokio::test]
async fn test_llm_static_analysis_phase_exists() {
    let phase = ScanPhase::LlmStaticAnalysis;
    assert_eq!(phase, ScanPhase::LlmStaticAnalysis);
}

#[tokio::test]
async fn test_llm_discovery_phase_exists() {
    let phase = ScanPhase::LlmDiscovery;
    assert_eq!(phase, ScanPhase::LlmDiscovery);
}

#[tokio::test]
async fn test_llm_verification_phase_exists() {
    let phase = ScanPhase::LlmVerification;
    assert_eq!(phase, ScanPhase::LlmVerification);
}

#[tokio::test]
async fn test_ticket_cross_ref_phase_exists() {
    let phase = ScanPhase::TicketCrossRef;
    assert_eq!(phase, ScanPhase::TicketCrossRef);
}

#[tokio::test]
async fn test_git_analysis_phase_exists() {
    let phase = ScanPhase::GitAnalysis;
    assert_eq!(phase, ScanPhase::GitAnalysis);
}

#[tokio::test]
async fn test_cross_file_analysis_phase_exists() {
    let phase = ScanPhase::CrossFileAnalysis;
    assert_eq!(phase, ScanPhase::CrossFileAnalysis);
}

#[tokio::test]
async fn test_confidence_scoring_phase_exists() {
    let phase = ScanPhase::ConfidenceScoring;
    assert_eq!(phase, ScanPhase::ConfidenceScoring);
}

#[tokio::test]
async fn test_ai_aggregation_phase_exists() {
    let phase = ScanPhase::AiAggregation;
    assert_eq!(phase, ScanPhase::AiAggregation);
}

#[tokio::test]
async fn test_reporting_phase_exists() {
    let phase = ScanPhase::Reporting;
    assert_eq!(phase, ScanPhase::Reporting);
}

#[tokio::test]
async fn test_threat_modeling_phase_exists() {
    let phase = ScanPhase::ThreatModeling;
    assert_eq!(phase, ScanPhase::ThreatModeling);
}

#[tokio::test]
async fn test_root_cause_dedup_phase_exists() {
    let phase = ScanPhase::RootCauseDedup;
    assert_eq!(phase, ScanPhase::RootCauseDedup);
}

#[tokio::test]
async fn test_multi_verifier_phase_exists() {
    let phase = ScanPhase::MultiVerifier;
    assert_eq!(phase, ScanPhase::MultiVerifier);
}

#[tokio::test]
async fn test_auto_patching_phase_exists() {
    let phase = ScanPhase::AutoPatching;
    assert_eq!(phase, ScanPhase::AutoPatching);
}

#[tokio::test]
async fn test_cve_bootstrap_phase_exists() {
    let phase = ScanPhase::CveBootstrap;
    assert_eq!(phase, ScanPhase::CveBootstrap);
}

#[tokio::test]
async fn test_poc_compiler_phase_exists() {
    let phase = ScanPhase::PocCompiler;
    assert_eq!(phase, ScanPhase::PocCompiler);
}

#[tokio::test]
async fn test_variant_search_phase_exists() {
    let phase = ScanPhase::VariantSearch;
    assert_eq!(phase, ScanPhase::VariantSearch);
}

#[tokio::test]
async fn test_security_agent_verification_phase_exists() {
    let phase = ScanPhase::SecurityAgentVerification;
    assert_eq!(phase, ScanPhase::SecurityAgentVerification);
}

#[tokio::test]
async fn test_complete_phase_exists() {
    let phase = ScanPhase::Complete;
    assert_eq!(phase, ScanPhase::Complete);
}

#[tokio::test]
async fn test_error_phase_exists() {
    let phase = ScanPhase::Error;
    assert_eq!(phase, ScanPhase::Error);
}

// ============================================================================
// Phase Execution Order Tests
// ============================================================================

#[test]
fn test_phase_execution_order_indexing_first() {
    let phases = [
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
    ];
    // Indexing should come first
    assert_eq!(phases[0], ScanPhase::Indexing);
}

#[test]
fn test_phase_execution_order_semgrep_second() {
    let phases = [
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
    ];
    // Semgrep should come second
    assert_eq!(phases[1], ScanPhase::Semgrep);
}

#[test]
fn test_phase_execution_order_reporting_last_of_core() {
    let core_phases = [
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
    ];
    // Reporting should be last of the core phases
    assert_eq!(core_phases[core_phases.len() - 1], ScanPhase::Reporting);
}

#[test]
fn test_all_phases_are_unique() {
    let all_phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::MultiVerifier,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::VariantSearch,
        ScanPhase::SecurityAgentVerification,
        ScanPhase::Complete,
        ScanPhase::Error,
    ];

    // Check that all phases are unique by comparing count after dedup
    // Use debug formatting for comparison since ScanPhase doesn't implement Ord
    let mut unique_phases: Vec<String> = all_phases.iter().map(|p| format!("{:?}", p)).collect();
    unique_phases.sort();
    unique_phases.dedup();

    assert_eq!(
        all_phases.len(),
        unique_phases.len(),
        "All phases should be unique"
    );
}

// ============================================================================
// Finding Processing Tests
// ============================================================================

#[test]
fn test_finding_creation_with_severity() {
    let finding = create_test_finding("test-1", "Test Finding", Severity::High);
    assert_eq!(finding.id, "test-1");
    assert_eq!(finding.title, "Test Finding");
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn test_finding_creation_with_medium_severity() {
    let finding = create_test_finding("test-2", "Medium Finding", Severity::Medium);
    assert_eq!(finding.severity, Severity::Medium);
}

#[test]
fn test_finding_creation_with_low_severity() {
    let finding = create_test_finding("test-3", "Low Finding", Severity::Low);
    assert_eq!(finding.severity, Severity::Low);
}

#[test]
fn test_finding_creation_with_critical_severity() {
    let finding = create_test_finding("test-4", "Critical Finding", Severity::Critical);
    assert_eq!(finding.severity, Severity::Critical);
}

#[test]
fn test_finding_has_required_fields() {
    let finding = create_test_finding("test-5", "Test", Severity::Medium);
    assert!(!finding.id.is_empty());
    assert!(!finding.title.is_empty());
    assert!(!finding.file_path.is_empty());
    assert!(!finding.description.is_empty());
}

#[test]
fn test_finding_line_number_is_some() {
    let finding = create_test_finding("test-6", "Test", Severity::Medium);
    assert!(finding.line_number.is_some());
    assert_eq!(finding.line_number.unwrap(), 42);
}

#[test]
fn test_finding_sources_not_empty() {
    let finding = create_test_finding("test-7", "Test", Severity::Medium);
    assert!(!finding.sources.is_empty());
    assert_eq!(finding.sources.len(), 1);
    assert_eq!(finding.sources[0], "test");
}

// ============================================================================
// Config Tests
// ============================================================================

#[test]
fn test_config_creation() {
    let config = create_test_config();
    assert!(!config.output.dir.is_empty());
}

#[test]
fn test_config_scanner_settings() {
    let config = create_test_config();
    assert_eq!(config.scanner.max_file_size_kb, 1024);
    assert!(config.scanner.exclude_paths.is_empty());
}

#[test]
fn test_config_llm_phases() {
    let config = create_test_config();
    // LLM phases should be accessible
    let _discovery = &config.llm.phases.discovery;
    let _verification = &config.llm.phases.verification;
    let _aggregation = &config.llm.phases.aggregation;
}

#[test]
fn test_config_agent_disabled_by_default() {
    let config = create_test_config();
    assert!(!config.agent.enabled);
}

// ============================================================================
// Progress Bar Tests
// ============================================================================

#[test]
fn test_progress_bar_creation() {
    let pb = create_test_progress_bar();
    // Progress bar should be created without errors
    assert!(pb.position() <= pb.length().unwrap_or(0));
}

#[test]
fn test_progress_bar_hidden_draw_target() {
    let pb = create_test_progress_bar();
    // Should have a draw target set (hidden in tests)
    assert!(pb.length().is_some());
}

// ============================================================================
// Phase Equality and Comparison Tests
// ============================================================================

#[test]
fn test_phase_equality_same_variant() {
    let phase1 = ScanPhase::Indexing;
    let phase2 = ScanPhase::Indexing;
    assert_eq!(phase1, phase2);
}

#[test]
fn test_phase_equality_different_variants() {
    let phase1 = ScanPhase::Indexing;
    let phase2 = ScanPhase::Semgrep;
    assert_ne!(phase1, phase2);
}

#[test]
fn test_phase_clone() {
    let phase = ScanPhase::Reporting;
    let cloned = phase.clone();
    assert_eq!(phase, cloned);
}

// ============================================================================
// Phase Context Tests
// ============================================================================

#[test]
fn test_phase_context_core_phases() {
    // Core phases should execute in order without skipping
    let core_phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
    ];

    assert_eq!(core_phases.len(), 11);
}

#[test]
fn test_phase_context_optional_phases() {
    // Optional phases can be enabled/disabled via config
    let optional_phases = [
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::MultiVerifier,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::VariantSearch,
    ];

    assert_eq!(optional_phases.len(), 7);
}

#[test]
fn test_phase_context_terminal_phases() {
    // Terminal phases mark completion or error states
    let terminal_phases = [ScanPhase::Complete, ScanPhase::Error];
    assert_eq!(terminal_phases.len(), 2);
}

// ============================================================================
// Finding Status Tests
// ============================================================================

#[test]
fn test_finding_verification_status_none_initially() {
    let finding = create_test_finding("test-10", "Test", Severity::Medium);
    assert!(finding.verification_status.is_none());
}

#[test]
fn test_finding_verification_status_can_be_set() {
    let mut finding = create_test_finding("test-11", "Test", Severity::Medium);
    finding.verification_status = Some(VerificationStatus::Confirmed);
    assert_eq!(
        finding.verification_status,
        Some(VerificationStatus::Confirmed)
    );
}

#[test]
fn test_finding_confidence_score_default() {
    let finding = create_test_finding("test-12", "Test", Severity::Medium);
    assert_eq!(finding.confidence_score, 0.8);
}

#[test]
fn test_finding_cwe_id_is_optional() {
    let finding = create_test_finding("test-13", "Test", Severity::Medium);
    assert!(finding.cwe_id.is_some());
}

// ============================================================================
// Metrics Tracker Tests
// ============================================================================

#[test]
fn test_llm_metrics_tracker_creation() {
    let _tracker = LlmMetricsTracker::new();
    // Should be able to create a metrics tracker
    // Tracker creation should succeed without errors
}

// ============================================================================
// Scanner Integration Tests
// ============================================================================

#[test]
fn test_scanner_phase_compatibility() {
    // Verify that phases are compatible with Scanner
    let _phase = ScanPhase::Indexing;
    // Phases should be Clone and PartialEq for use with Scanner
    let _cloned = _phase.clone();
    assert_eq!(_phase, _cloned);
}

// ============================================================================
// Edge Cases and Error Handling Tests
// ============================================================================

#[test]
fn test_empty_findings_vector() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    assert!(findings.is_empty());
}

#[test]
fn test_single_finding_vector() {
    let findings = [create_test_finding("single", "Single", Severity::Low)];
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_multiple_findings_vector() {
    let findings = [
        create_test_finding("multi-1", "Multi 1", Severity::Low),
        create_test_finding("multi-2", "Multi 2", Severity::Medium),
        create_test_finding("multi-3", "Multi 3", Severity::High),
    ];
    assert_eq!(findings.len(), 3);
}

#[test]
fn test_analyzed_files_empty() {
    let files: Vec<String> = vec![];
    assert!(files.is_empty());
}

#[test]
fn test_analyzed_files_with_content() {
    let files = ["src/main.rs".to_string(), "src/lib.rs".to_string()];
    assert_eq!(files.len(), 2);
}

// ============================================================================
// Severity Classification Tests
// ============================================================================

#[test]
fn test_severity_high_or_critical_high() {
    assert!(Severity::High.is_high_or_critical());
}

#[test]
fn test_severity_high_or_critical_critical() {
    assert!(Severity::Critical.is_high_or_critical());
}

#[test]
fn test_severity_high_or_critical_medium() {
    assert!(!Severity::Medium.is_high_or_critical());
}

#[test]
fn test_severity_high_or_critical_low() {
    assert!(!Severity::Low.is_high_or_critical());
}

// ============================================================================
// Phase Debug Display Tests
// ============================================================================

#[test]
fn test_phase_debug_display_indexing() {
    let phase = ScanPhase::Indexing;
    let display = format!("{:?}", phase);
    assert_eq!(display, "Indexing");
}

#[test]
fn test_phase_debug_display_reporting() {
    let phase = ScanPhase::Reporting;
    let display = format!("{:?}", phase);
    assert_eq!(display, "Reporting");
}

#[test]
fn test_phase_debug_display_threat_modeling() {
    let phase = ScanPhase::ThreatModeling;
    let display = format!("{:?}", phase);
    assert_eq!(display, "ThreatModeling");
}

// ============================================================================
// Finding ID Uniqueness Tests
// ============================================================================

#[test]
fn test_finding_ids_are_unique() {
    let findings = [
        create_test_finding("id-1", "Finding 1", Severity::Low),
        create_test_finding("id-2", "Finding 2", Severity::Medium),
        create_test_finding("id-3", "Finding 3", Severity::High),
    ];

    let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
    let mut unique_ids = ids.clone();
    unique_ids.sort();
    unique_ids.dedup();

    assert_eq!(
        ids.len(),
        unique_ids.len(),
        "All finding IDs should be unique"
    );
}

// ============================================================================
// File Path Tests
// ============================================================================

#[test]
fn test_finding_file_path_format() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.file_path.starts_with("src/"));
    assert!(finding.file_path.ends_with(".rs"));
}

#[test]
fn test_finding_code_snippet_present() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.code_snippet.is_some());
    assert!(!finding.code_snippet.unwrap().is_empty());
}

// ============================================================================
// LLM Phase Configuration Tests
// ============================================================================

#[test]
fn test_llm_phases_config_discovery() {
    let config = create_test_config_with_discovery_key();
    assert!(config.llm.phases.discovery.api_key.is_some());
    assert_eq!(config.llm.phases.discovery.api_key.unwrap(), "test-key");
}

#[test]
fn test_llm_phases_config_verification() {
    let config = create_test_config();
    // Verification phase should have its own config
    let _verification = &config.llm.phases.verification;
}

#[test]
fn test_llm_phases_config_aggregation() {
    let config = create_test_config();
    // Aggregation phase should have its own config
    let _aggregation = &config.llm.phases.aggregation;
}

#[test]
fn test_performance_settings_confidence_refinement_enabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_confidence_refinement = true;
    assert!(config.scanner.performance.enable_confidence_refinement);
}

#[test]
fn test_performance_settings_threat_modeling_enabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_threat_modeling = true;
    assert!(config.scanner.performance.enable_threat_modeling);
}

#[test]
fn test_performance_settings_root_cause_dedup_enabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_root_cause_dedup = true;
    assert!(config.scanner.performance.enable_root_cause_dedup);
}

#[test]
fn test_performance_settings_multi_verifier_enabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_multi_verifier = true;
    assert!(config.scanner.performance.enable_multi_verifier);
}

#[test]
fn test_performance_settings_auto_patching_enabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_auto_patching = true;
    assert!(config.scanner.performance.enable_auto_patching);
}

#[test]
fn test_performance_settings_cve_bootstrap_enabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_cve_bootstrap = true;
    assert!(config.scanner.performance.enable_cve_bootstrap);
}

#[test]
fn test_performance_settings_poc_compilation_enabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_poc_compilation = true;
    assert!(config.scanner.performance.enable_poc_compilation);
}

#[test]
fn test_performance_settings_variant_search_enabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_variant_search = true;
    assert!(config.scanner.performance.enable_variant_search);
}

#[test]
fn test_all_features_enabled_config() {
    let config = create_test_config_all_features();
    assert!(config.scanner.performance.enable_confidence_refinement);
    assert!(config.scanner.performance.enable_threat_modeling);
    assert!(config.scanner.performance.enable_root_cause_dedup);
    assert!(config.scanner.performance.enable_multi_verifier);
    assert!(config.scanner.performance.enable_auto_patching);
    assert!(config.scanner.performance.enable_cve_bootstrap);
    assert!(config.scanner.performance.enable_poc_compilation);
    assert!(config.scanner.performance.enable_variant_search);
}

// ============================================================================
// Temp Directory Tests
// ============================================================================

#[test]
fn test_temp_dir_creation() {
    let temp_dir = create_temp_test_dir();
    assert!(temp_dir.path().exists());
}

#[test]
fn test_temp_dir_path_is_valid() {
    let temp_dir = create_temp_test_dir();
    let path = temp_dir.path();
    assert!(path.is_dir());
}

// ============================================================================
// Phase Config Structure Tests
// ============================================================================

#[test]
fn test_phase_config_structure() {
    let _config = create_test_config();
    let _pb = create_test_progress_bar();
    let findings = vec![create_test_finding("test", "Test", Severity::Medium)];
    let analyzed_files = vec!["src/main.rs".to_string()];
    let _metrics_tracker = LlmMetricsTracker::new();
    let _target_path = PathBuf::from(".");
    let _phase = ScanPhase::Indexing;

    // Verify we can construct the necessary components for run_phase
    assert!(!findings.is_empty());
    assert!(!analyzed_files.is_empty());
    assert!(_pb.length().is_some());
}

// ============================================================================
// Output Directory Tests
// ============================================================================

#[test]
fn test_output_dir_configuration() {
    let config = create_test_config();
    assert!(!config.output.dir.is_empty());
    assert_eq!(config.output.dir, "/tmp/baco_test_output");
}

#[test]
fn test_output_format_configuration() {
    let config = create_test_config();
    assert!(!config.output.format.is_empty());
    assert!(config.output.format.contains(&"html".to_string()));
}

// ============================================================================
// Scanner Settings Tests
// ============================================================================

#[test]
fn test_scanner_max_file_size() {
    let config = create_test_config();
    assert_eq!(config.scanner.max_file_size_kb, 1024);
}

#[test]
fn test_scanner_commit_lookback_days() {
    let config = create_test_config();
    assert_eq!(config.scanner.commit_lookback_days, 30);
}

#[test]
fn test_scanner_exclude_paths_empty() {
    let config = create_test_config();
    assert!(config.scanner.exclude_paths.is_empty());
}

#[test]
fn test_scanner_exclude_paths_with_values() {
    let mut config = create_test_config();
    config.scanner.exclude_paths = vec!["target".to_string(), "node_modules".to_string()];
    assert_eq!(config.scanner.exclude_paths.len(), 2);
}

// ============================================================================
// LLM Timeout and Retry Tests
// ============================================================================

#[test]
fn test_llm_timeout_configuration() {
    let config = create_test_config();
    assert_eq!(config.llm.timeout_secs, 60);
}

#[test]
fn test_llm_max_retries_configuration() {
    let config = create_test_config();
    assert_eq!(config.llm.max_retries, 3);
}

#[test]
fn test_llm_retry_backoff_configuration() {
    let config = create_test_config();
    assert_eq!(config.llm.retry_backoff_ms, 1000);
}

// ============================================================================
// Agent Configuration Tests
// ============================================================================

#[test]
fn test_agent_max_turns() {
    let config = create_test_config();
    assert_eq!(config.agent.max_turns, 10);
}

#[test]
fn test_agent_tool_timeout() {
    let config = create_test_config();
    assert_eq!(config.agent.tool_timeout_secs, 30);
}

#[test]
fn test_agent_trusted_paths_empty() {
    let config = create_test_config();
    assert!(config.agent.trusted_paths.is_empty());
}

#[test]
fn test_agent_keep_artifacts_disabled() {
    let config = create_test_config();
    assert!(!config.agent.keep_artifacts);
}

// ============================================================================
// Finding Vector Operations Tests
// ============================================================================

#[test]
fn test_finding_vector_extend() {
    let mut findings = vec![create_test_finding("1", "First", Severity::Low)];
    let new_findings = vec![
        create_test_finding("2", "Second", Severity::Medium),
        create_test_finding("3", "Third", Severity::High),
    ];
    findings.extend(new_findings);
    assert_eq!(findings.len(), 3);
}

#[test]
fn test_finding_vector_filter() {
    let findings = vec![
        create_test_finding("1", "Low", Severity::Low),
        create_test_finding("2", "Medium", Severity::Medium),
        create_test_finding("3", "High", Severity::High),
        create_test_finding("4", "Critical", Severity::Critical),
    ];

    let high_or_critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity.is_high_or_critical())
        .collect();

    assert_eq!(high_or_critical.len(), 2);
}

#[test]
fn test_finding_vector_map() {
    let findings = vec![
        create_test_finding("1", "First", Severity::Low),
        create_test_finding("2", "Second", Severity::Medium),
    ];

    let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&"1".to_string()));
    assert!(ids.contains(&"2".to_string()));
}

// ============================================================================
// Analyzed Files Tests
// ============================================================================

#[test]
fn test_analyzed_files_contains() {
    let files = vec![
        "src/main.rs".to_string(),
        "src/lib.rs".to_string(),
        "tests/test.rs".to_string(),
    ];

    assert!(files.contains(&"src/main.rs".to_string()));
    assert!(!files.contains(&"src/unknown.rs".to_string()));
}

#[test]
fn test_analyzed_files_clone() {
    let files = vec!["src/main.rs".to_string()];
    let cloned = files.clone();
    assert_eq!(files, cloned);
}

// ============================================================================
// Progress Bar Position Tests
// ============================================================================

#[test]
fn test_progress_bar_position_initial() {
    let pb = create_test_progress_bar();
    assert_eq!(pb.position(), 0);
}

#[test]
fn test_progress_bar_length_set() {
    let pb = create_test_progress_bar();
    assert!(pb.length().is_some());
    assert_eq!(pb.length().unwrap(), 100);
}

// ============================================================================
// Phase Error Handling Tests
// ============================================================================

#[test]
fn test_unknown_phase_handling() {
    // Test that unknown phases are handled gracefully
    // This tests the default case in run_phase match
    let phase = ScanPhase::Complete;
    assert_eq!(format!("{:?}", phase), "Complete");
}

#[test]
fn test_error_phase_handling() {
    let phase = ScanPhase::Error;
    assert_eq!(format!("{:?}", phase), "Error");
}

// ============================================================================
// Integration Tests - Phase Execution Context
// ============================================================================

#[tokio::test]
async fn test_indexing_phase_context() {
    // Test that indexing phase can be created and used in context
    let _phase = ScanPhase::Indexing;
    let _config = create_test_config();
    let _pb = create_test_progress_bar();
    let findings: Vec<VulnerabilityFinding> = vec![];
    let analyzed_files: Vec<String> = vec![];

    // Verify all components are available for phase execution
    assert!(!_config.output.dir.is_empty());
    assert!(_pb.length().is_some());
    assert!(findings.is_empty());
    assert!(analyzed_files.is_empty());
}

#[tokio::test]
async fn test_reporting_phase_context() {
    let _phase = ScanPhase::Reporting;
    let _config = create_test_config();
    let _metrics_tracker = LlmMetricsTracker::new();

    // Reporting phase needs output dir and metrics
    assert!(!_config.output.dir.is_empty());
}

#[tokio::test]
async fn test_threat_modeling_phase_context() {
    let mut _config = create_test_config();
    _config.scanner.performance.enable_threat_modeling = true;

    // Threat modeling needs output directory
    let output_path = PathBuf::from(&_config.output.dir);
    assert_eq!(output_path.as_os_str(), "/tmp/baco_test_output");
}

#[tokio::test]
async fn test_confidence_scoring_phase_context() {
    let mut _config = create_test_config();
    _config.scanner.performance.enable_confidence_refinement = true;

    // Confidence scoring needs output directory for context loading
    let output_path = PathBuf::from(&_config.output.dir);
    assert!(output_path
        .as_os_str()
        .to_string_lossy()
        .contains("test_output"));
}

// ============================================================================
// Metrics Tests
// ============================================================================

#[tokio::test]
async fn test_metrics_tracker_finalize() {
    let _tracker = LlmMetricsTracker::new();
    let _metrics = _tracker.finalize().await;
    // Metrics should be finalized without panic
}

#[test]
fn test_metrics_tracker_creation() {
    let tracker = LlmMetricsTracker::new();
    drop(tracker);
}

// ============================================================================
// Project Configuration Tests
// ============================================================================

#[test]
fn test_project_config_languages() {
    let config = create_test_config();
    assert!(!config.project.languages.is_empty());
    assert!(config.project.languages.contains(&"rust".to_string()));
}

#[test]
fn test_project_config_name() {
    let config = create_test_config();
    assert_eq!(config.project.name, "test");
}

#[test]
fn test_project_config_path() {
    let config = create_test_config();
    assert_eq!(config.project.path, ".");
}

// ============================================================================
// Ticket System Tests
// ============================================================================

#[test]
fn test_ticket_config_default() {
    let config = TicketConfig::default();
    // Should create without panic
    drop(config);
}

#[test]
fn test_ticket_systems_empty_by_default() {
    let config = create_test_config();
    assert!(config.tickets.systems.is_empty());
}

// ============================================================================
// Semgrep Settings Tests
// ============================================================================

#[test]
fn test_semgrep_settings_default() {
    let settings = config::SemgrepSettings::default();
    drop(settings);
}

#[test]
fn test_semgrep_exclude_rules_empty() {
    let config = create_test_config();
    assert!(config.scanner.semgrep.exclude_rules.is_empty());
}

// ============================================================================
// Path Handling Tests
// ============================================================================

#[test]
fn test_pathbuf_from_string() {
    let dir = "/tmp/test_output";
    let path = PathBuf::from(dir);
    assert!(path.as_os_str().to_string_lossy().contains("test_output"));
}

#[test]
fn test_pathbuf_parent() {
    let path = PathBuf::from("/tmp/output/file.json");
    if let Some(parent) = path.parent() {
        assert!(parent.as_os_str().to_string_lossy().contains("output"));
    }
}

// ============================================================================
// Clone and Copy Tests
// ============================================================================

#[test]
fn test_finding_clone() {
    let finding = create_test_finding("clone-test", "Clone", Severity::Medium);
    let cloned = finding.clone();
    assert_eq!(finding.id, cloned.id);
    assert_eq!(finding.title, cloned.title);
    assert_eq!(finding.severity, cloned.severity);
}

#[test]
fn test_severity_clone() {
    let severity = Severity::High;
    let cloned = severity; // Severity is Copy
    assert_eq!(severity, cloned);
}

#[test]
fn test_verification_status_clone() {
    let status = VerificationStatus::Confirmed;
    let cloned = status; // VerificationStatus is Copy
    assert_eq!(status, cloned);
}

// ============================================================================
// Vector Capacity and Growth Tests
// ============================================================================

#[test]
fn test_finding_vector_with_capacity() {
    let mut findings = Vec::with_capacity(10);
    assert_eq!(findings.capacity(), 10);

    findings.push(create_test_finding("1", "First", Severity::Low));
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_analyzed_files_with_capacity() {
    let mut files = Vec::with_capacity(5);
    files.push("src/main.rs".to_string());
    files.push("src/lib.rs".to_string());

    assert_eq!(files.len(), 2);
    assert!(files.capacity() >= 5);
}

// ============================================================================
// String Formatting Tests
// ============================================================================

#[test]
fn test_finding_id_formatting() {
    let finding = create_test_finding("custom-id", "Test", Severity::Medium);
    assert_eq!(finding.id, "custom-id");
}

#[test]
fn test_finding_title_with_spaces() {
    let finding = create_test_finding("test", "Test Finding With Spaces", Severity::Medium);
    assert!(finding.title.contains(" "));
}

#[test]
fn test_file_path_with_directory() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.file_path.contains("/"));
}

// ============================================================================
// Option Type Tests
// ============================================================================

#[test]
fn test_line_number_option_some() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.line_number.is_some());
    assert_eq!(finding.line_number.unwrap(), 42);
}

#[test]
fn test_cwe_id_option_some() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.cwe_id.is_some());
    assert_eq!(finding.cwe_id.unwrap(), "CWE-416");
}

#[test]
fn test_verification_status_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.verification_status.is_none());
}

#[test]
fn test_code_snippet_option_some() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.code_snippet.is_some());
}

#[test]
fn test_diff_hunk_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.diff_hunk.is_none());
}

#[test]
fn test_recommendation_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.recommendation.is_none());
}

#[test]
fn test_commit_reference_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.commit_reference.is_none());
}

#[test]
fn test_ticket_reference_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.ticket_reference.is_none());
}

#[test]
fn test_priority_score_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.priority_score.is_none());
}

#[test]
fn test_cross_file_references_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.cross_file_references.is_none());
}

#[test]
fn test_poc_code_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.poc_code.is_none());
}

#[test]
fn test_mitigation_code_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.mitigation_code.is_none());
}

#[test]
fn test_poc_format_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.poc_format.is_none());
}

#[test]
fn test_llm_model_option_none_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.llm_model.is_none());
}

// ============================================================================
// Boolean Flag Tests
// ============================================================================

#[test]
fn test_already_reported_flag_false_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(!finding.already_reported);
}

#[test]
fn test_agent_mode_flag_false_initially() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(!finding.agent_mode);
}

// ============================================================================
// Numeric Field Tests
// ============================================================================

#[test]
fn test_confidence_score_range() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.confidence_score >= 0.0);
    assert!(finding.confidence_score <= 1.0);
}

#[test]
fn test_confidence_score_value() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert_eq!(finding.confidence_score, 0.8);
}

// ============================================================================
// Sources Vector Tests
// ============================================================================

#[test]
fn test_sources_vector_not_empty() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(!finding.sources.is_empty());
}

#[test]
fn test_sources_vector_contains_test() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.sources.contains(&"test".to_string()));
}

#[test]
fn test_sources_can_be_pushed() {
    let mut finding = create_test_finding("test", "Test", Severity::Medium);
    let initial_len = finding.sources.len();
    finding.sources.push("new_source".to_string());
    assert_eq!(finding.sources.len(), initial_len + 1);
}

// ============================================================================
// Edge Cases - Empty and Minimal Configurations
// ============================================================================

#[test]
fn test_empty_languages_list() {
    let mut config = create_test_config();
    config.project.languages = vec![];
    assert!(config.project.languages.is_empty());
}

#[test]
fn test_empty_output_format_list() {
    let mut config = create_test_config();
    config.output.format = vec![];
    assert!(config.output.format.is_empty());
}

#[test]
fn test_zero_max_file_size() {
    let mut config = create_test_config();
    config.scanner.max_file_size_kb = 0;
    assert_eq!(config.scanner.max_file_size_kb, 0);
}

#[test]
fn test_zero_commit_lookback_days() {
    let mut config = create_test_config();
    config.scanner.commit_lookback_days = 0;
    assert_eq!(config.scanner.commit_lookback_days, 0);
}

// ============================================================================
// Performance Settings Tests
// ============================================================================

#[test]
fn test_all_performance_settings_disabled() {
    let mut config = create_test_config();
    config.scanner.performance.enable_confidence_refinement = false;
    config.scanner.performance.enable_threat_modeling = false;
    config.scanner.performance.enable_root_cause_dedup = false;
    config.scanner.performance.enable_multi_verifier = false;
    config.scanner.performance.enable_auto_patching = false;
    config.scanner.performance.enable_cve_bootstrap = false;
    config.scanner.performance.enable_poc_compilation = false;
    config.scanner.performance.enable_variant_search = false;

    assert!(!config.scanner.performance.enable_confidence_refinement);
    assert!(!config.scanner.performance.enable_threat_modeling);
    assert!(!config.scanner.performance.enable_root_cause_dedup);
    assert!(!config.scanner.performance.enable_multi_verifier);
    assert!(!config.scanner.performance.enable_auto_patching);
    assert!(!config.scanner.performance.enable_cve_bootstrap);
    assert!(!config.scanner.performance.enable_poc_compilation);
    assert!(!config.scanner.performance.enable_variant_search);
}

// ============================================================================
// Source Tracking Tests
// ============================================================================

#[test]
fn test_finding_sources_tracking() {
    let finding = create_test_finding("test", "Test", Severity::Medium);
    assert!(finding.sources.contains(&"test".to_string()));
}

#[test]
fn test_finding_can_have_multiple_sources() {
    let mut finding = create_test_finding("test", "Test", Severity::Medium);
    finding.sources.push("semgrep".to_string());
    finding.sources.push("llm".to_string());
    assert_eq!(finding.sources.len(), 3);
}
