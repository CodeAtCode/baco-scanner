// Tests migrated from src/scanner/mod.rs inline #[cfg(test)] block

use baco::checkpoint::ScanPhase;
use baco::config::{
    AgentConfig, LlmPhasesConfig, PerformanceSettings, ScannerConfig, ScannerSettings,
};
use baco::findings::Severity;
use baco::phase::helpers::create_test_finding_simple;
use baco::scanner::Scanner;
use indicatif::ProgressBar;
use std::path::PathBuf;

fn create_test_config() -> ScannerConfig {
    ScannerConfig {
        project: baco::config::ProjectConfig {
            languages: vec!["rust".to_string()],
            ..Default::default()
        },
        scanner: ScannerSettings {
            max_file_size_kb: 1024,
            exclude_paths: vec![],
            semgrep: Default::default(),
            performance: PerformanceSettings::default(),
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
        router: Default::default(),
        aggregation: Default::default(),
        rulesynth: Default::default(),
        normalization: Default::default(),
        cpg: Default::default(),
        exploit: Default::default(),
        validate: Default::default(),
        vultriage: Default::default(),
        policy_sampling: Default::default(),
        agent_scaffold: Default::default(),
        pacvd: Default::default(),
        agent_flow: Default::default(),
        vuln_spec: Default::default(),
        citation_verification: Default::default(),
        triage: Default::default(),
        priority: Default::default(),
        budget: Default::default(),
        prior_runs: Default::default(),
        org_context: Default::default(),
        knowledge: Default::default(),
    }
}

#[test]
fn test_scan_phase_all_variants_exist() {
    let phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::CweRouting,
        ScanPhase::CpgSlice,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::Validate,
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
        ScanPhase::RuleSynthesis,
        ScanPhase::ExploitSynth,
        ScanPhase::Complete,
        ScanPhase::Error,
    ];

    assert_eq!(phases.len(), 26);
}

#[test]
fn test_scan_phase_debug_format() {
    assert_eq!(format!("{:?}", ScanPhase::Indexing), "Indexing");
    assert_eq!(format!("{:?}", ScanPhase::Semgrep), "Semgrep");
    assert_eq!(
        format!("{:?}", ScanPhase::LlmStaticAnalysis),
        "LlmStaticAnalysis"
    );
    assert_eq!(format!("{:?}", ScanPhase::Complete), "Complete");
}

#[tokio::test]
async fn test_indexing_phase_empty_findings() {
    let config = create_test_config();
    let pb = ProgressBar::new(100);
    let target_path = PathBuf::from(".");

    let scanner = Scanner::new(config.clone(), target_path.clone(), false);

    let result = scanner
        .run_phase(&ScanPhase::Indexing, vec![], &pb, &[])
        .await;
    assert!(result.is_ok());

    let (findings, analyzed_files, _rejected) = result.unwrap();
    assert!(findings.is_empty());
    assert_eq!(analyzed_files.len(), 0);
}

#[tokio::test]
async fn test_cross_file_analysis_phase() {
    let config = create_test_config();
    let pb = ProgressBar::new(100);
    let target_path = PathBuf::from(".");

    let findings = vec![
        create_test_finding_simple("Cross File 1", Severity::Medium),
        create_test_finding_simple("Cross File 2", Severity::Medium),
    ];

    let scanner = Scanner::new(config.clone(), target_path.clone(), false);
    let result = scanner
        .run_phase(&ScanPhase::CrossFileAnalysis, findings, &pb, &[])
        .await;

    assert!(result.is_ok());
    let (findings, _, _) = result.unwrap();
    assert_eq!(findings.len(), 2);
}

#[tokio::test]
async fn test_reporting_phase() {
    let config = create_test_config();
    let pb = ProgressBar::new(100);
    let target_path = PathBuf::from(".");

    let findings = vec![
        create_test_finding_simple("Report 1", Severity::Critical),
        create_test_finding_simple("Report 2", Severity::High),
        create_test_finding_simple("Report 3", Severity::Medium),
    ];

    let scanner = Scanner::new(config.clone(), target_path.clone(), false);
    let result = scanner
        .run_phase(&ScanPhase::Reporting, findings, &pb, &[])
        .await;

    assert!(result.is_ok());
    let (findings, _, _) = result.unwrap();
    assert_eq!(findings.len(), 3);
}

#[tokio::test]
async fn test_phase_with_mixed_severities() {
    let config = create_test_config();
    let pb = ProgressBar::new(100);
    let target_path = PathBuf::from(".");

    let findings = vec![
        create_test_finding_simple("Critical Issue", Severity::Critical),
        create_test_finding_simple("High Issue", Severity::High),
        create_test_finding_simple("Medium Issue", Severity::Medium),
        create_test_finding_simple("Low Issue", Severity::Low),
    ];

    let scanner = Scanner::new(config.clone(), target_path.clone(), false);
    let result = scanner
        .run_phase(&ScanPhase::CrossFileAnalysis, findings, &pb, &[])
        .await;

    assert!(result.is_ok());
    let (findings, _, _) = result.unwrap();
    assert_eq!(findings.len(), 4);
}
