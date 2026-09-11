//! Tests for scan health reporting

use baco::checkpoint::ScanPhase;
use baco::llm_metrics::LlmMetrics;
use baco::report::json::write_findings_json;
use baco::scan_health::{from_llm_metrics, LlmOutcomeClass, PhaseStatusKind, ScanHealth};

use std::fs;
use std::path::Path;

#[test]
fn test_scan_health_default() {
    let health = ScanHealth::default();
    assert!(health.phase_status.is_empty());
    assert_eq!(health.files.indexed, 0);
    assert_eq!(health.total_tokens, 0);
}

#[test]
fn test_record_phase_run() {
    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    assert_eq!(health.phase_status.len(), 1);
    assert!(matches!(
        health.phase_status[0].status,
        PhaseStatusKind::Run
    ));
    assert_eq!(health.phase_status[0].phase, "Indexing");
}

#[test]
fn test_record_phase_skipped_with_reason() {
    let mut health = ScanHealth::new();
    health.record_phase_skipped(
        &ScanPhase::LlmDiscovery,
        "incomplete llm.phases.discovery config",
    );
    assert_eq!(health.phase_status.len(), 1);
    assert!(matches!(
        health.phase_status[0].status,
        PhaseStatusKind::Skipped
    ));
    assert_eq!(
        health.phase_status[0].reason,
        Some("incomplete llm.phases.discovery config".to_string())
    );
}

#[test]
fn test_file_counters() {
    let mut health = ScanHealth::new();
    health.set_indexed(100);
    health.set_analyzed(80);
    health.set_dropped_by_size(5);
    health.set_chunked(10);
    health.set_truncated(3);

    assert_eq!(health.files.indexed, 100);
    assert_eq!(health.files.analyzed, 80);
    assert_eq!(health.files.dropped_by_size, 5);
    assert_eq!(health.files.chunked, 10);
    assert_eq!(health.files.truncated, 3);
}

#[test]
fn test_llm_outcomes() {
    let mut health = ScanHealth::new();
    health.record_llm_outcome(&LlmOutcomeClass::Ok);
    health.record_llm_outcome(&LlmOutcomeClass::Ok);
    health.record_llm_outcome(&LlmOutcomeClass::AuthFailure);

    assert_eq!(health.llm_outcomes.get("ok"), Some(&2));
    assert_eq!(health.llm_outcomes.get("auth_failure"), Some(&1));
}

#[test]
fn test_token_recording() {
    let mut health = ScanHealth::new();
    health.record_tokens(&ScanPhase::LlmDiscovery, 100, 50);
    health.record_tokens(&ScanPhase::LlmVerification, 200, 100);

    assert_eq!(health.total_tokens, 450);
    assert_eq!(health.tokens_by_phase.len(), 2);
    assert_eq!(health.tokens_by_phase[0].total_tokens, 150);
    assert_eq!(health.tokens_by_phase[1].total_tokens, 300);
}

#[test]
fn test_budget_status() {
    let mut health = ScanHealth::new();
    health.set_budget(Some(1000), 250);

    assert_eq!(health.budget.cap_maybe, Some(1000));
    assert_eq!(health.budget.used, 250);
    assert!((health.budget.pct_of_cap.unwrap() - 25.0).abs() < 0.01);
}

#[test]
fn test_all_llm_phases_skipped() {
    let mut health = ScanHealth::new();
    // Record all LLM phases as skipped
    health.record_phase_skipped(&ScanPhase::LlmStaticAnalysis, "no API key");
    health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
    health.record_phase_skipped(&ScanPhase::LlmVerification, "no API key");
    health.record_phase_skipped(&ScanPhase::SecurityAgentVerification, "no API key");

    assert!(health.all_llm_phases_skipped());
}

#[test]
fn test_blind_marker_when_all_llm_skipped() {
    let mut health = ScanHealth::new();
    // Skip all LLM phases with no successes
    health.record_phase_skipped(&ScanPhase::LlmStaticAnalysis, "no API key");
    health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
    health.record_phase_skipped(&ScanPhase::LlmVerification, "no API key");
    health.record_phase_skipped(&ScanPhase::SecurityAgentVerification, "no API key");
    health.set_llm_counts(0, 0);

    assert_eq!(
        health.blind_marker(),
        Some("SCAN PARTIALLY BLIND: LLM phases skipped — check config".to_string())
    );
}

#[test]
fn test_no_blind_marker_when_llm_ran() {
    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::LlmDiscovery);
    health.record_phase_skipped(&ScanPhase::LlmVerification, "no API key");
    health.set_llm_counts(5, 0);

    assert!(health.blind_marker().is_none());
}

#[test]
fn test_summary_generation() {
    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
    health.set_indexed(50);
    health.set_analyzed(40);
    health.set_llm_counts(0, 0);

    let summary = health.summary();
    assert!(summary.contains("phases: 1/1 run/skipped"));
    assert!(summary.contains("files: 50 indexed, 40 analyzed"));
    assert!(summary.contains("llm: 0/0 ok/failed"));
}

#[test]
fn test_serialization_roundtrip() {
    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
    health.set_indexed(100);
    health.set_llm_counts(5, 2);

    let json = serde_json::to_string(&health).unwrap();
    let parsed: ScanHealth = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.phase_status.len(), 2);
    assert_eq!(parsed.files.indexed, 100);
    assert_eq!(parsed.llm_ok, 5);
    assert_eq!(parsed.llm_failed, 2);
}

#[test]
fn test_json_report_contains_scan_health_section() {
    let findings: Vec<baco::findings::VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_scan_health_json.json";

    let _ = fs::remove_file(output_path);

    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
    health.set_indexed(50);
    health.set_llm_counts(5, 0);

    // include_rejected triggers the full report object shape, which carries the summary sections
    let mut config = baco::config::ScannerConfig::default();
    config.output.include_rejected = true;

    let result = write_findings_json(
        &findings,
        &[],
        output_path,
        None,
        Some(&config),
        None,
        Some(health),
    );

    assert!(result.is_ok());
    assert!(Path::new(output_path).exists());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("scan_health"));
    assert!(content.contains("phase_status"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_from_llm_metrics_helper() {
    let metrics = LlmMetrics {
        total_success: 10,
        total_failed: 3,
        ..Default::default()
    };

    let (ok, failed) = from_llm_metrics(&metrics);
    assert_eq!(ok, 10);
    assert_eq!(failed, 3);
}

#[test]
fn test_simulated_pipeline_run() {
    // Simulate a full pipeline run with various outcomes
    let mut health = ScanHealth::new();

    // Record phases
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_run(&ScanPhase::Semgrep);
    health.record_phase_skipped(
        &ScanPhase::LlmDiscovery,
        "incomplete llm.phases.discovery config",
    );
    health.record_phase_run(&ScanPhase::CweRouting);

    // Record file counters
    health.set_indexed(150);
    health.set_analyzed(120);
    health.set_dropped_by_size(10);
    health.set_chunked(20);

    // Record LLM outcomes
    health.record_llm_outcome(&LlmOutcomeClass::Ok);
    health.record_llm_outcome(&LlmOutcomeClass::Ok);
    health.record_llm_outcome(&LlmOutcomeClass::AuthFailure);
    health.set_llm_counts(2, 1);

    // Record token usage
    health.record_tokens(&ScanPhase::LlmStaticAnalysis, 500, 200);

    // Set budget
    health.set_budget(Some(10000), 700);

    // Verify
    assert_eq!(health.phase_status.len(), 4);
    assert_eq!(health.files.indexed, 150);
    assert_eq!(health.llm_ok, 2);
    assert_eq!(health.llm_failed, 1);
    assert_eq!(health.total_tokens, 700);
}
