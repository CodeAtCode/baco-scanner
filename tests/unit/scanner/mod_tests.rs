// Tests migrated from src/scanner/mod.rs inline #[cfg(test)] block

use baco::checkpoint::ScanPhase;

use baco::findings::Severity;
use baco::phase::helpers::create_test_finding_simple;
use baco::scanner::Scanner;
use indicatif::ProgressBar;
use std::path::PathBuf;

use crate::fixtures::create_test_config;

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

    assert_eq!(phases.len(), 25);
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
