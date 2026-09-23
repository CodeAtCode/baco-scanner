#![cfg(test)]
#![allow(clippy::field_reassign_with_default)]

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

/// Helper for testing phases that skip when disabled or missing config
async fn run_phase_skip_test(
    phase: ScanPhase,
    config_modifier: impl Fn(&mut config::ScannerConfig),
) {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config_modifier(&mut config);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];
    let phase_config = PhaseConfig {
        phase: &phase,
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
// Indexing Phase Tests
// ============================================================================

#[tokio::test]
async fn test_indexing_phase_preserves_findings() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files = vec!["test.py".to_string()];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
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
    assert_eq!(updated.len(), 1);
}

// ============================================================================
// Semgrep Phase Tests
// ============================================================================

#[tokio::test]
async fn test_semgrep_phase_error_handling() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from("/nonexistent");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("existing-1", Severity::Medium)];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Semgrep,
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
}

// ============================================================================
// Validate Phase Tests
// ============================================================================

#[tokio::test]
async fn test_phases_skip_when_disabled() {
    /// Config modification strategy
    enum ConfigModifier {
        ValidateDisabled,
        ValidateNoApiKey,
        ConfidenceScoringDisabled,
        ThreatModelingDisabled,
        RootCauseDedupDisabled,
        AutoPatchingDisabled,
        CveBootstrapDisabled,
        PocCompilerDisabled,
        VariantSearchDisabled,
        CweRoutingDisabled,
        RuleSynthesisDisabled,
        RuleSynthesisNoApiKey,
        ExploitSynthDisabled,
        ExploitSynthNoApiKey,
        CpgSliceDisabled,
    }

    fn apply_modifier(config: &mut config::ScannerConfig, modifier: ConfigModifier) {
        match modifier {
            ConfigModifier::ValidateDisabled => {
                config.validate.enabled = false;
            }
            ConfigModifier::ValidateNoApiKey => {
                config.validate.enabled = true;
                config.llm.phases.verification.api_key = None;
            }
            ConfigModifier::ConfidenceScoringDisabled => {
                config.scanner.performance.enable_confidence_refinement = false;
            }
            ConfigModifier::ThreatModelingDisabled => {
                config.scanner.performance.enable_threat_modeling = false;
            }
            ConfigModifier::RootCauseDedupDisabled => {
                config.scanner.performance.enable_root_cause_dedup = false;
            }
            ConfigModifier::AutoPatchingDisabled => {
                config.scanner.performance.enable_auto_patching = false;
            }
            ConfigModifier::CveBootstrapDisabled => {
                config.scanner.performance.enable_cve_bootstrap = false;
            }
            ConfigModifier::PocCompilerDisabled => {
                config.scanner.performance.enable_poc_compilation = false;
            }
            ConfigModifier::VariantSearchDisabled => {
                config.scanner.performance.enable_variant_search = false;
            }
            ConfigModifier::CweRoutingDisabled => {
                config.router.enabled = false;
            }
            ConfigModifier::RuleSynthesisDisabled => {
                config.rulesynth.enabled = false;
            }
            ConfigModifier::RuleSynthesisNoApiKey => {
                config.rulesynth.enabled = true;
                config.llm.phases.discovery.api_key = None;
            }
            ConfigModifier::ExploitSynthDisabled => {
                config.exploit.enabled = false;
            }
            ConfigModifier::ExploitSynthNoApiKey => {
                config.exploit.enabled = true;
                config.llm.phases.discovery.api_key = None;
            }
            ConfigModifier::CpgSliceDisabled => {
                config.cpg.enabled = false;
            }
        }
    }

    // Test case: (phase, config_modifier, description)
    let test_cases = vec![
        (
            ScanPhase::Validate,
            ConfigModifier::ValidateDisabled,
            "validate_disabled",
        ),
        (
            ScanPhase::Validate,
            ConfigModifier::ValidateNoApiKey,
            "validate_no_api_key",
        ),
        (
            ScanPhase::ConfidenceScoring,
            ConfigModifier::ConfidenceScoringDisabled,
            "confidence_scoring_disabled",
        ),
        (
            ScanPhase::ThreatModeling,
            ConfigModifier::ThreatModelingDisabled,
            "threat_modeling_disabled",
        ),
        (
            ScanPhase::RootCauseDedup,
            ConfigModifier::RootCauseDedupDisabled,
            "root_cause_dedup_disabled",
        ),
        (
            ScanPhase::AutoPatching,
            ConfigModifier::AutoPatchingDisabled,
            "auto_patching_disabled",
        ),
        (
            ScanPhase::CveBootstrap,
            ConfigModifier::CveBootstrapDisabled,
            "cve_bootstrap_disabled",
        ),
        (
            ScanPhase::PocCompiler,
            ConfigModifier::PocCompilerDisabled,
            "poc_compiler_disabled",
        ),
        (
            ScanPhase::VariantSearch,
            ConfigModifier::VariantSearchDisabled,
            "variant_search_disabled",
        ),
        (
            ScanPhase::CweRouting,
            ConfigModifier::CweRoutingDisabled,
            "cwe_routing_disabled",
        ),
        (
            ScanPhase::RuleSynthesis,
            ConfigModifier::RuleSynthesisDisabled,
            "rule_synthesis_disabled",
        ),
        (
            ScanPhase::RuleSynthesis,
            ConfigModifier::RuleSynthesisNoApiKey,
            "rule_synthesis_no_api_key",
        ),
        (
            ScanPhase::ExploitSynth,
            ConfigModifier::ExploitSynthDisabled,
            "exploit_synth_disabled",
        ),
        (
            ScanPhase::ExploitSynth,
            ConfigModifier::ExploitSynthNoApiKey,
            "exploit_synth_no_api_key",
        ),
        (
            ScanPhase::CpgSlice,
            ConfigModifier::CpgSliceDisabled,
            "cpg_slice_disabled",
        ),
    ];

    for (phase, modifier, description) in test_cases {
        let scanner = create_test_scanner();
        let mut config = create_test_config();
        apply_modifier(&mut config, modifier);
        let pb = ProgressBar::hidden();
        let metrics_tracker = LlmMetricsTracker::new();
        let analyzed_files: Vec<String> = vec![];
        let target_path = PathBuf::from(".");
        let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
        let findings = vec![create_test_finding("test-1", Severity::High)];
        let phase_config = PhaseConfig {
            phase: &phase,
            findings: findings.clone(),
            pb: &pb,
            analyzed_files: &analyzed_files,
            metrics_tracker: &metrics_tracker,
            target_path: &target_path,
            config: &config,
            project_stack: &project_stack,
        };

        let result = run_phase(&scanner, phase_config).await;
        assert!(
            result.is_ok(),
            "Phase {:?} ({}) should complete without error",
            phase,
            description
        );
        let (updated, _, _) = result.unwrap();
        assert_eq!(
            updated.len(),
            findings.len(),
            "Phase {:?} ({}) should preserve finding count when skipped",
            phase,
            description
        );
    }
}

// ============================================================================
// Ticket Cross-Reference Phase Tests
// ============================================================================

#[tokio::test]
async fn test_ticket_crossref_skips_when_empty_systems() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::TicketCrossRef,
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
// Git Analysis Phase Tests
// ============================================================================

#[tokio::test]
async fn test_git_analysis_on_valid_repo() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![
        create_test_finding("git-1", Severity::High),
        create_test_finding("git-2", Severity::Medium),
    ];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::GitAnalysis,
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
// Cross-File Analysis Phase Tests
// ============================================================================

#[tokio::test]
async fn test_cross_file_analysis_basic() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![
        create_test_finding("cross-1", Severity::High),
        create_test_finding("cross-2", Severity::Critical),
    ];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::CrossFileAnalysis,
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
    assert!(updated.len() >= findings.len());
}

// ============================================================================
// Reporting Phase Tests
// ============================================================================

#[tokio::test]
async fn test_reporting_phase_basic() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.output.dir = "/tmp/test_reporting".to_string();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![
        create_test_finding("report-1", Severity::High),
        create_test_finding("report-2", Severity::Critical),
    ];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Reporting,
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
async fn test_reporting_phase_empty_findings() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.output.dir = "/tmp/test_reporting_empty".to_string();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings: Vec<VulnerabilityFinding> = vec![];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Reporting,
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
    assert!(updated.is_empty());
}

// ============================================================================
// Reporting Phase Tests
// ============================================================================

// ============================================================================
// Edge Case Tests
// ============================================================================

#[tokio::test]
async fn test_empty_findings_handling() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings: Vec<VulnerabilityFinding> = vec![];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
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
    assert!(updated.is_empty());
}

#[tokio::test]
async fn test_large_finding_count_handling() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings: Vec<VulnerabilityFinding> = (0..100)
        .map(|i| create_test_finding(&format!("bulk-{}", i), Severity::High))
        .collect();
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
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
async fn test_mixed_severity_findings_indexing() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![
        create_test_finding("sev-1", Severity::Critical),
        create_test_finding("sev-2", Severity::High),
        create_test_finding("sev-3", Severity::Medium),
        create_test_finding("sev-4", Severity::Low),
    ];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
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
async fn test_analyzed_files_preserved() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files = vec![
        "file1.py".to_string(),
        "file2.rs".to_string(),
        "file3.js".to_string(),
    ];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
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
    let (_, updated_analyzed_files, _) = result.unwrap();
    assert_eq!(updated_analyzed_files.len(), analyzed_files.len());
}

#[tokio::test]
async fn test_all_phases_complete_without_error() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];
    let phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::VariantSearch,
        ScanPhase::CweRouting,
    ];
    let mut current_findings = findings.clone();
    for phase in phases {
        let phase_config = PhaseConfig {
            phase: &phase,
            findings: current_findings.clone(),
            pb: &pb,
            analyzed_files: &analyzed_files,
            metrics_tracker: &metrics_tracker,
            target_path: &target_path,
            config: &config,
            project_stack: &project_stack,
        };
        let result = run_phase(&scanner, phase_config).await;
        assert!(result.is_ok(), "Phase {:?} failed", phase);
        current_findings = result.unwrap().0;
    }
    assert!(current_findings.len() >= findings.len());
}

#[tokio::test]
async fn test_complete_phase_marker() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("complete-1", Severity::High)];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Complete,
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
async fn test_phase_with_single_finding() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("single-1", Severity::Critical)];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
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
    assert_eq!(updated.len(), 1);
}

#[tokio::test]
async fn test_phase_preserves_finding_metadata() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let mut finding = create_test_finding("meta-1", Severity::High);
    finding.cwe_id = Some("CWE-79".to_string());
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];
    let findings = vec![finding];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
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
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].id, "meta-1");
}
// --- Tests migrated from scanner_phases_inline_tests.rs ---

#[tokio::test]
async fn test_llm_static_analysis_skips_without_api_key() {
    run_phase_skip_test(ScanPhase::LlmStaticAnalysis, |c| {
        c.llm.phases.discovery.api_key = None;
    })
    .await;
}

#[tokio::test]
async fn test_llm_discovery_skips_without_api_key() {
    run_phase_skip_test(ScanPhase::LlmDiscovery, |c| {
        c.llm.phases.discovery.api_key = None;
    })
    .await;
}

#[tokio::test]
async fn test_llm_verification_skips_without_api_key() {
    run_phase_skip_test(ScanPhase::LlmVerification, |c| {
        c.llm.phases.verification.api_key = None;
    })
    .await;
}

#[tokio::test]
async fn test_security_agent_skips_when_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High)];
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
async fn test_threat_modeling_phase_basic() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    // Disable threat modeling to test the phase logic without LLM calls
    config.scanner.performance.enable_threat_modeling = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("threat-1", Severity::High)];
    let phase_config = PhaseConfig {
        phase: &ScanPhase::ThreatModeling,
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
async fn test_phase_chain_preserves_all_findings() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let initial_findings = vec![
        create_test_finding("chain-1", Severity::Critical),
        create_test_finding("chain-2", Severity::High),
    ];
    let mut current_findings = initial_findings.clone();
    let phases = vec![
        ScanPhase::Indexing,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
    ];
    current_findings = run_phase_list(
        &phases,
        &scanner,
        current_findings,
        analyzed_files,
        &pb,
        &metrics_tracker,
        &target_path,
        &config,
        &project_stack,
    )
    .await;
    assert!(current_findings.len() >= initial_findings.len());
}

/// Helper to run a list of phases sequentially
#[allow(clippy::too_many_arguments)]
async fn run_phase_list(
    phases: &[ScanPhase],
    scanner: &Scanner,
    mut current_findings: Vec<VulnerabilityFinding>,
    analyzed_files: Vec<String>,
    pb: &ProgressBar,
    metrics_tracker: &LlmMetricsTracker,
    target_path: &std::path::Path,
    config: &config::ScannerConfig,
    project_stack: &Option<baco::scanner_types::project::ProjectStack>,
) -> Vec<VulnerabilityFinding> {
    for phase in phases {
        let phase_config = PhaseConfig {
            phase,
            findings: current_findings.clone(),
            pb,
            analyzed_files: &analyzed_files,
            metrics_tracker,
            target_path,
            config,
            project_stack,
        };
        let result = run_phase(scanner, phase_config).await.unwrap();
        current_findings = result.0;
    }
    current_findings
}

#[tokio::test]
async fn test_indexing_phase_with_many_findings() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    // Create 50 findings to test batch handling
    let findings: Vec<VulnerabilityFinding> = (0..50)
        .map(|i| create_test_finding(&format!("bulk-{}", i), Severity::High))
        .collect();

    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    assert_eq!(result.0.len(), 50);
}

#[tokio::test]
async fn test_semgrep_phase_with_nonexistent_path() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from("/nonexistent/path/that/does/not/exist");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("sem-1", Severity::Medium)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::Semgrep,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when path doesn't exist
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_llm_static_analysis_without_api_key() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.llm.phases.static_analysis.api_key = None;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("llm-static-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::LlmStaticAnalysis,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when API key is missing
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_llm_discovery_without_api_key() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.llm.phases.discovery.api_key = None;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("llm-disc-1", Severity::Critical)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::LlmDiscovery,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when API key is missing
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_llm_verification_without_api_key() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.llm.phases.verification.api_key = None;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("llm-ver-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::LlmVerification,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when API key is missing
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_security_agent_verification_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.agent.enabled = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("agent-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::SecurityAgentVerification,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when agent is disabled
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_ticket_crossref_with_empty_systems() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("ticket-1", Severity::Medium)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::TicketCrossRef,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when no ticket systems configured
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_confidence_scoring_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_confidence_refinement = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("conf-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::ConfidenceScoring,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when confidence refinement is disabled
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_root_cause_dedup_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_root_cause_dedup = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("dedup-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::RootCauseDedup,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when dedup is disabled
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_auto_patching_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_auto_patching = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("patch-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::AutoPatching,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when auto-patching is disabled
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_cve_bootstrap_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_cve_bootstrap = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("cve-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::CveBootstrap,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when CVE bootstrap is disabled
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_poc_compiler_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_poc_compilation = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("poc-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::PocCompiler,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when PoC compilation is disabled
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_variant_search_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_variant_search = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("variant-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::VariantSearch,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when variant search is disabled
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_threat_modeling_disabled() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_threat_modeling = false;
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("threat-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::ThreatModeling,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    // Should return findings unchanged when threat modeling is disabled
    assert_eq!(result.0.len(), 1);
}

#[tokio::test]
async fn test_mixed_severity_findings_crossfile() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    let findings = vec![
        create_test_finding("crit", Severity::Critical),
        create_test_finding("high", Severity::High),
        create_test_finding("med", Severity::Medium),
        create_test_finding("low", Severity::Low),
    ];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    assert_eq!(result.0.len(), 4);
}

#[tokio::test]
async fn test_phase_chain_with_all_phases() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    let initial_findings = vec![create_test_finding("chain", Severity::High)];
    let mut current_findings = initial_findings.clone();

    let phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
    ];

    current_findings = run_phase_list(
        &phases,
        &scanner,
        current_findings,
        analyzed_files,
        &pb,
        &metrics_tracker,
        &target_path,
        &config,
        &project_stack,
    )
    .await;

    assert!(current_findings.len() >= initial_findings.len());
}

#[tokio::test]
async fn test_finding_metadata_preservation() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    let mut finding = create_test_finding("meta", Severity::Critical);
    finding.cwe_id = Some("CWE-89".to_string());
    finding.sources = vec!["semgrep".to_string(), "manual".to_string()];
    finding.priority_score = Some(0.95);

    let findings = vec![finding];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await.unwrap();
    assert_eq!(result.0.len(), 1);
    assert_eq!(result.0[0].cwe_id, Some("CWE-89".to_string()));
    assert_eq!(result.0[0].sources.len(), 2);
}

// PhaseConfig tests
#[test]
fn test_phase_config_construction() {
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let findings = vec![create_test_finding("test", Severity::High)];
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
        findings: findings.clone(),
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    assert_eq!(phase_config.findings.len(), 1);
    assert!(phase_config.analyzed_files.is_empty());
}

// Indexing phase with real files
#[tokio::test]
async fn test_indexing_phase_with_temp_files() {
    use tempfile::tempdir;

    let scanner = create_test_scanner();
    let mut config = create_test_config();

    let tmp_dir = tempdir().unwrap();
    config.output.dir = tmp_dir.path().to_string_lossy().to_string();

    // Create a test file
    let test_file = tmp_dir.path().join("test.rs");
    std::fs::write(&test_file, "fn main() {}").unwrap();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = tmp_dir.path().to_path_buf();
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::Indexing,
        findings,
        pb: &pb,
        analyzed_files: &analyzed_files,
        metrics_tracker: &metrics_tracker,
        target_path: &target_path,
        config: &config,
        project_stack: &project_stack,
    };

    let result = run_phase(&scanner, phase_config).await;
    assert!(result.is_ok());
    tmp_dir.close().unwrap();
}

// ============================================================================
// Security Agent Verification Phase Tests - None Branch
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_llm_client_unavailable() {
    // Test the None branch of create_llm_client_with_metrics
    // Triggered when: agent.enabled == true AND api_key is Some() BUT
    // create_llm_client_with_metrics returns None (incomplete LLM config - no base_url)
    let scanner = create_test_scanner();
    let mut config = create_test_config();

    // Enable agent and set API key
    config.agent.enabled = true;
    config.llm.phases.security_agent_verification.api_key = Some("test-key".to_string());

    // Leave base_url empty in both global and phase config to trigger phase_llm_config error
    // This causes create_llm_client_with_metrics to return None
    config.llm.base_url = String::new();
    config.llm.phases.security_agent_verification.base_url = String::new();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    let mut finding = create_test_finding("agent-llm-unavailable", Severity::High);
    finding.title = "Test SQL Injection".to_string();
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
    assert!(
        result.is_ok(),
        "Phase should complete successfully even when LLM client is unavailable"
    );

    let (updated, _, _) = result.unwrap();

    // The None branch returns findings unchanged
    assert_eq!(
        updated.len(),
        findings.len(),
        "Findings should be returned unchanged when LLM client is unavailable"
    );

    // Verify the finding is unchanged
    assert_eq!(updated[0].id, findings[0].id);
}

// ConfidenceScoring with actual findings
#[tokio::test]
async fn test_confidence_scoring_with_findings() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_confidence_refinement = true;

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![
        create_test_finding("conf-1", Severity::High),
        create_test_finding("conf-2", Severity::Critical),
    ];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::ConfidenceScoring,
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

// RootCauseDedup with actual findings
#[tokio::test]
async fn test_root_cause_dedup_with_findings() {
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_root_cause_dedup = true;

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![
        create_test_finding("dedup-1", Severity::High),
        create_test_finding("dedup-2", Severity::Medium),
    ];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::RootCauseDedup,
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
    assert!(updated.len() <= findings.len());
}

// TicketCrossRef with empty systems (no-op but not skipped)
#[tokio::test]
async fn test_ticket_crossref_empty_systems_noop() {
    let scanner = create_test_scanner();
    let config = create_test_config();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("ticket-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::TicketCrossRef,
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
    // No ticket reference should be set
    assert!(updated[0].ticket_reference.is_none());
}

// LlmVerification with findings
#[tokio::test]
async fn test_llm_verification_with_findings() {
    let scanner = create_test_scanner();
    let config = create_test_config();

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("verify-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::LlmVerification,
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

// ExploitSynth with disabled config
#[test]
fn test_exploit_synth_disabled() {
    use baco::config::ExploitConfig;

    let mut config = ExploitConfig::default();
    config.enabled = false;
    assert!(!config.enabled);
}

// RuleSynthesis with disabled config
#[test]
fn test_rule_synthesis_disabled() {
    use baco::config::RuleSynthConfig;

    let mut config = RuleSynthConfig::default();
    config.enabled = false;
    assert!(!config.enabled);
}

// Test ScanPhase unknown variant handling
#[tokio::test]
async fn test_unknown_phase_handling() {
    let scanner = create_test_scanner();
    let config = create_test_config();
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("unknown-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::CveBootstrap,
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
}
#[tokio::test]
async fn test_llm_verification_batch_path_with_mockito() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"choices": [{"message": {"content": "[{\"index\": 0, \"verification_status\": \"confirmed\", \"verification_notes\": \"yes\"}, {\"index\": 1, \"verification_status\": \"false_positive\", \"verification_notes\": \"no\"}]"}}]}"#,
        )
        .create();

    let mut config = create_test_config();
    config.llm.phases.verification.base_url = server.url();
    config.llm.phases.verification.api_key = Some("k".to_string());
    config.llm.phases.verification.models = vec!["mock-model".to_string()];
    config.agent.enabled = false;

    let scanner = Scanner::new(config.clone(), PathBuf::from("."), false);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("test-1", Severity::High), {
        let mut second = create_test_finding("test-2", Severity::High);
        second.title = "Other Vulnerability".to_string();
        second.file_path = "other.py".to_string();
        second.line_number = Some(7);
        second
    }];
    let phase = ScanPhase::LlmVerification;
    let phase_config = PhaseConfig {
        phase: &phase,
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
    let (updated, _, rejected) = result.unwrap();
    assert_eq!(updated.len(), 1);
    assert_eq!(
        updated[0].verification_status,
        Some(VerificationStatus::Confirmed)
    );
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].0.id, "test-2");
    assert_eq!(rejected[0].1, "no");
}
#[tokio::test]
async fn test_llm_static_analysis_phase_with_mockito() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"choices": [{"message": {"content": "[{\"severity\": \"high\", \"title\": \"Buffer Overflow\", \"description\": \"Potential buffer overflow\", \"line\": 2, \"cwe_id\": \"CWE-120\"}]"}}]}"#,
        )
        .create();

    let temp = TempDir::new().unwrap();
    std::fs::write(
        temp.path().join("vuln.rs"),
        "fn vuln() {\n    let x = 1;\n}\n",
    )
    .unwrap();

    let mut config = create_test_config();
    config.llm.phases.static_analysis.base_url = server.url();
    config.llm.phases.static_analysis.api_key = Some("k".to_string());
    config.llm.phases.static_analysis.models = vec!["mock-model".to_string()];
    config.project.languages = vec!["rust".to_string()];
    config.triage.enabled = false;
    config.priority.enabled = false;
    config.vuln_spec.enabled = false;
    config.scanner.performance.enable_file_filtering = false;
    config.output.dir = temp.path().to_string_lossy().to_string();

    let scanner = Scanner::new(config.clone(), temp.path().to_path_buf(), false);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = temp.path().to_path_buf();
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let phase = ScanPhase::LlmStaticAnalysis;
    let phase_config = PhaseConfig {
        phase: &phase,
        findings: vec![],
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
    assert!(
        !updated.is_empty(),
        "static analysis should report the mocked finding"
    );
}
#[tokio::test]
async fn test_llm_discovery_enrichment_with_mockito() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"choices": [{"message": {"content": "{\"description\": \"enriched desc\", \"fix_code\": \"patched()\"}"}}]}"#,
        )
        .create();

    let temp = TempDir::new().unwrap();
    let mut config = create_test_config();
    config.llm.phases.discovery.base_url = server.url();
    config.llm.phases.discovery.api_key = Some("k".to_string());
    config.llm.phases.discovery.models = vec!["mock-model".to_string()];
    config.agent.enabled = false;
    config.prior_runs.enabled = false;
    config.scanner.performance.enable_hunt_prompts = false;
    config.output.dir = temp.path().to_string_lossy().to_string();

    let scanner = Scanner::new(config.clone(), temp.path().to_path_buf(), false);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = temp.path().to_path_buf();
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let mut finding = create_test_finding("test-1", Severity::High);
    finding.evidence = Vec::new();
    let phase = ScanPhase::LlmDiscovery;
    let phase_config = PhaseConfig {
        phase: &phase,
        findings: vec![finding],
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
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].description, "enriched desc");
    assert_eq!(updated[0].diff_hunk.as_deref(), Some("patched()"));
}
#[tokio::test]
async fn test_llm_static_analysis_triage_cascade_with_mockito() {
    let temp = TempDir::new().unwrap();
    let vuln_path = temp.path().join("vuln.rs").to_string_lossy().to_string();
    let safe_path = temp.path().join("safe.rs").to_string_lossy().to_string();
    std::fs::write(
        temp.path().join("vuln.rs"),
        "fn vuln() {\n    let x = 1;\n}\n",
    )
    .unwrap();
    std::fs::write(
        temp.path().join("safe.rs"),
        "fn safe() {\n    let y = 2;\n}\n",
    )
    .unwrap();

    let mut server = mockito::Server::new_async().await;

    let findings_inner = format!(
        "{{\"findings\": [{{\"file\": \"{}\", \"summary_one_line\": \"vuln\", \"suspicion\": 0.8, \"reason\": \"test\"}}, {{\"file\": \"{}\", \"summary_one_line\": \"safe\", \"suspicion\": 0.1, \"reason\": \"test\"}}]}}",
        vuln_path.replace('"', "\\\""),
        safe_path.replace('"', "\\\"")
    );
    let triage_body = format!(
        "{{\"choices\": [{{\"message\": {{\"content\": \"{}\"}}}}]}}",
        findings_inner.replace('"', "\\\"")
    );
    let _triage_mock = server
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::Regex("security triage".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(triage_body)
        .create();

    let analysis_body = r#"{"choices": [{"message": {"content": "[{\"severity\": \"high\", \"title\": \"Buffer Overflow\", \"description\": \"Potential buffer overflow\", \"line\": 2, \"cwe_id\": \"CWE-120\"}]"}}]}"#;
    let _analysis_mock = server
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::Regex("security expert".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(analysis_body)
        .create();

    let mut config = create_test_config();
    config.llm.phases.static_analysis.base_url = server.url();
    config.llm.phases.static_analysis.api_key = Some("k".to_string());
    config.llm.phases.static_analysis.models = vec!["mock-model".to_string()];
    config.project.languages = vec!["rust".to_string()];
    config.triage.enabled = true;
    config.triage.suspicion_threshold = 0.5;
    config.priority.enabled = false;
    config.vuln_spec.enabled = false;
    config.scanner.performance.enable_file_filtering = false;
    config.output.dir = temp.path().to_string_lossy().to_string();

    let scanner = Scanner::new(config.clone(), temp.path().to_path_buf(), false);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = temp.path().to_path_buf();
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let phase = ScanPhase::LlmStaticAnalysis;
    let phase_config = PhaseConfig {
        phase: &phase,
        findings: vec![],
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
    assert!(
        !updated.is_empty(),
        "triage should pass vuln.rs to analysis and produce findings"
    );
    assert!(
        updated.iter().all(|f| f.file_path.ends_with("vuln.rs")),
        "only vuln.rs should be analyzed (safe.rs below threshold)"
    );
}

// ============================================================================
// Phase Mockito Tests (Validate, RuleSynthesis, ExploitSynth)
// ============================================================================

#[tokio::test]
async fn test_validate_phase_with_mockito() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"choices": [{"message": {"content": "{\"is_sound\": true, \"issues\": [], \"confidence_adjustment\": 0.1}"}}]}"#,
        )
        .create();

    let mut config = create_test_config();
    config.validate.enabled = true;
    config.llm.phases.verification.base_url = server.url();
    config.llm.phases.verification.api_key = Some("k".to_string());
    config.llm.phases.verification.models = vec!["mock-model".to_string()];

    let scanner = Scanner::new(config.clone(), PathBuf::from("."), false);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let finding = create_test_finding("test-1", Severity::High);
    let phase = ScanPhase::Validate;
    let phase_config = PhaseConfig {
        phase: &phase,
        findings: vec![finding],
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
    assert_eq!(updated.len(), 1);
    assert!(
        updated[0].confidence_score > 0.9,
        "sound verdict should boost confidence above baseline"
    );
}

#[tokio::test]
async fn test_rule_synthesis_phase_with_mockito() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"choices": [{"message": {"content": "rules:\n  - id: cwe-89-test\n    pattern: execute($X)\n    message: test\n    languages: [python]\n    severity: ERROR"}}]}"#,
        )
        .create();

    let temp = TempDir::new().unwrap();
    let mut config = create_test_config();
    config.rulesynth.enabled = true;
    config.rulesynth.mocq_mode = false;
    config.rulesynth.output_dir = temp.path().to_path_buf();
    config.llm.phases.discovery.base_url = server.url();
    config.llm.phases.discovery.api_key = Some("k".to_string());
    config.llm.phases.discovery.models = vec!["mock-model".to_string()];
    config.project.languages = vec!["python".to_string()];

    let scanner = Scanner::new(config.clone(), temp.path().to_path_buf(), false);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = temp.path().to_path_buf();
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let finding = create_test_finding("test-1", Severity::High);
    let phase = ScanPhase::RuleSynthesis;
    let phase_config = PhaseConfig {
        phase: &phase,
        findings: vec![finding],
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
    assert_eq!(updated.len(), 1, "findings returned unchanged");
}

#[tokio::test]
async fn test_exploit_synth_phase_sandbox_unavailable() {
    let server = mockito::Server::new_async().await;
    let mut config = create_test_config();
    config.exploit.enabled = true;
    config.llm.phases.discovery.base_url = server.url();
    config.llm.phases.discovery.api_key = Some("k".to_string());
    config.llm.phases.discovery.models = vec!["mock-model".to_string()];

    let scanner = Scanner::new(config.clone(), PathBuf::from("."), false);
    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let finding = create_test_finding("test-1", Severity::High);
    let phase = ScanPhase::ExploitSynth;
    let phase_config = PhaseConfig {
        phase: &phase,
        findings: vec![finding],
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
    assert_eq!(
        updated.len(),
        1,
        "findings returned unchanged when sandbox unavailable"
    );
}
// ============================================================================
// Security Agent Verification Skip Tests
// ============================================================================

#[tokio::test]
async fn test_security_agent_verification_skips_when_agent_disabled() {
    run_phase_skip_test(ScanPhase::SecurityAgentVerification, |cfg| {
        cfg.agent.enabled = false;
    })
    .await;
}

#[tokio::test]
async fn test_security_agent_verification_skips_when_no_api_key() {
    run_phase_skip_test(ScanPhase::SecurityAgentVerification, |cfg| {
        cfg.agent.enabled = true;
        cfg.llm.phases.security_agent_verification.api_key = None;
    })
    .await;
}

#[tokio::test]
async fn test_llm_static_analysis_skips_when_no_api_key() {
    run_phase_skip_test(ScanPhase::LlmStaticAnalysis, |cfg| {
        cfg.llm.phases.static_analysis.api_key = None;
    })
    .await;
}

// ============================================================================
// PoC Compiler Phase Tests - Enabled Path Coverage
// ============================================================================

#[tokio::test]
async fn test_poc_compiler_phase_with_poc_code_unsupported_language() {
    // Covers run_poc_compiler lines 112-135: enabled path with poc_code set
    // Uses unsupported language "ruby" to trigger the else branch (Failed + notes)
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_poc_compilation = true;

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    // Create a finding with poc_code and unsupported language
    let mut finding = create_test_finding("poc-test-1", Severity::High);
    finding.poc_code = Some("puts 'hello'".to_string());
    finding.poc_format = Some("ruby".to_string());
    let findings = vec![finding];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::PocCompiler,
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

    // Verify the finding was updated with Failed status and notes
    assert_eq!(
        updated[0].verification_status,
        Some(VerificationStatus::Failed)
    );
    assert!(updated[0].verification_notes.is_some());
    assert!(
        updated[0]
            .verification_notes
            .as_ref()
            .unwrap()
            .contains("PoC compilation failed")
    );
}

#[tokio::test]
async fn test_poc_compiler_phase_without_poc_code() {
    // Covers run_poc_compiler: finding without poc_code (no-op path)
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_poc_compilation = true;

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;

    // Create a finding without poc_code
    let findings = vec![create_test_finding("poc-test-2", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::PocCompiler,
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

    // Verify the finding was unchanged (no poc_code means no verification)
    // Note: create_test_finding sets verification_status to Confirmed by default
    assert_eq!(
        updated[0].verification_status,
        Some(VerificationStatus::Confirmed)
    );
}

// ============================================================================
// Variant Search Phase Tests - No-Patterns Branch Coverage
// ============================================================================

#[tokio::test]
async fn test_variant_search_phase_no_patterns_configured() {
    // Covers run_variant_search lines 162-173: enabled but no patterns
    let scanner = create_test_scanner();
    let mut config = create_test_config();
    config.scanner.performance.enable_variant_search = true;
    // variant_search_patterns is empty by default

    let pb = ProgressBar::hidden();
    let metrics_tracker = LlmMetricsTracker::new();
    let analyzed_files: Vec<String> = vec![];
    let target_path = PathBuf::from(".");
    let project_stack: Option<baco::scanner_types::project::ProjectStack> = None;
    let findings = vec![create_test_finding("variant-test-1", Severity::High)];

    let phase_config = PhaseConfig {
        phase: &ScanPhase::VariantSearch,
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

    // Verify finding count unchanged (early return with warning)
    assert_eq!(updated[0].id, findings[0].id);
}
