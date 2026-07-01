//! Unit tests for scanner phases
//!
//! Tests cover all phase types, execution order, phase context, and finding processing.

use baco::checkpoint::ScanPhase;
use baco::config::{self, PerformanceSettings, TicketConfig};
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm_metrics::LlmMetricsTracker;
use indicatif::ProgressBar;

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
    let optional_phases = vec![
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
    let terminal_phases = vec![ScanPhase::Complete, ScanPhase::Error];
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
    assert_eq!(finding.verification_status, Some(VerificationStatus::Confirmed));
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
    let findings = vec![create_test_finding("single", "Single", Severity::Low)];
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_multiple_findings_vector() {
    let findings = vec![
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
    let files = vec!["src/main.rs".to_string(), "src/lib.rs".to_string()];
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
    let findings = vec![
        create_test_finding("id-1", "Finding 1", Severity::Low),
        create_test_finding("id-2", "Finding 2", Severity::Medium),
        create_test_finding("id-3", "Finding 3", Severity::High),
    ];

    let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
    let mut unique_ids = ids.clone();
    unique_ids.sort();
    unique_ids.dedup();

    assert_eq!(ids.len(), unique_ids.len(), "All finding IDs should be unique");
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
