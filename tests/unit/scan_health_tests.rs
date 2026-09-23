//! Tests for scan health reporting

use baco::checkpoint::ScanPhase;
use baco::llm::metrics::LlmMetrics;
use baco::report::json::write_findings_json;
use baco::scan_health::{LlmOutcomeClass, PhaseStatusKind, ScanHealth, from_llm_metrics};

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
    assert!(summary.contains("phases: 1 run, 1 skipped"));
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

    let (ok, failed) = from_llm_metrics(&metrics, None);
    assert_eq!(ok, 10);
    assert_eq!(failed, 3);
}

#[test]
fn test_profile_skip_entries_in_health() {
    // Test that profile-skipped phases are recorded when profile=core
    use baco::scan_health::PhaseStatusKind;

    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_skipped(
        &ScanPhase::CpgSlice,
        "profile=core excludes experimental phase",
    );
    health.record_phase_run(&ScanPhase::Semgrep);

    assert_eq!(health.phase_status.len(), 3);

    let cpg_entry = health
        .phase_status
        .iter()
        .find(|ps| ps.phase == "CpgSlice")
        .unwrap();
    assert!(matches!(cpg_entry.status, PhaseStatusKind::Skipped));
    assert_eq!(
        cpg_entry.reason,
        Some("profile=core excludes experimental phase".to_string())
    );
}

#[test]
fn test_llm_config_skip_entry_contains_phase_slot() {
    // Test that LLM-skip entries mention the phase's config slot
    use baco::scan_health::PhaseStatusKind;

    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_skipped(
        &ScanPhase::LlmDiscovery,
        "no API key configured (set llm.phases.discovery.api_key)",
    );

    let discovery_entry = health
        .phase_status
        .iter()
        .find(|ps| ps.phase == "LlmDiscovery")
        .unwrap();
    assert!(matches!(discovery_entry.status, PhaseStatusKind::Skipped));
    assert!(
        discovery_entry
            .reason
            .as_ref()
            .unwrap()
            .contains("llm.phases.discovery")
    );
}

#[test]
fn test_no_skipped_line_when_nothing_skipped() {
    // Test that a scan with nothing skipped has an empty list and no skipped-line
    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_run(&ScanPhase::Semgrep);
    health.record_phase_run(&ScanPhase::LlmStaticAnalysis);

    let summary = health.summary();
    assert!(!summary.contains("skipped ("));
    assert!(summary.contains("phases: 3 run, 0 skipped"));
}

#[test]
fn test_json_serialization_includes_phase_status_entries() {
    // Test that JSON serialization includes the phase status entries
    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_skipped(
        &ScanPhase::CpgSlice,
        "profile=core excludes experimental phase",
    );
    health.record_phase_skipped(
        &ScanPhase::LlmDiscovery,
        "no API key configured (set llm.phases.discovery.api_key)",
    );
    health.set_indexed(50);

    let json = serde_json::to_string_pretty(&health).unwrap();

    // Verify phase_status is included
    assert!(json.contains("phase_status"));
    assert!(json.contains("CpgSlice"));
    assert!(json.contains("LlmDiscovery"));
    assert!(json.contains("profile=core excludes experimental phase"));
    assert!(json.contains("llm.phases.discovery"));

    // Verify deserialization works
    let parsed: ScanHealth = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.phase_status.len(), 3);
    assert_eq!(parsed.files.indexed, 50);
}

#[test]
fn test_detect_llm_config_skips() {
    use baco::config::llm::LlmPhasesConfig;

    let mut config = LlmPhasesConfig::default();
    // discovery has no API key
    config.discovery.api_key = None;
    // verification has API key
    config.verification.api_key = Some("test-key".to_string());
    // static_analysis has no API key
    config.static_analysis.api_key = None;
    // security_agent_verification has API key
    config.security_agent_verification.api_key = Some("test-key".to_string());

    // Phases that already ran
    let ran_phases = vec!["Indexing".to_string(), "Semgrep".to_string()];

    let skips = ScanHealth::detect_llm_config_skips(&config, &ran_phases);

    assert_eq!(skips.len(), 2);

    // Check that discovery and static_analysis are in the skips
    let skip_phases: Vec<_> = skips.iter().map(|(p, _)| p).collect();
    assert!(skip_phases.contains(&&ScanPhase::LlmDiscovery));
    assert!(skip_phases.contains(&&ScanPhase::LlmStaticAnalysis));

    // Check reasons mention config slots
    for (phase, reason) in &skips {
        if *phase == ScanPhase::LlmDiscovery {
            assert!(reason.contains("llm.phases.discovery"));
        } else if *phase == ScanPhase::LlmStaticAnalysis {
            assert!(reason.contains("llm.phases.static_analysis"));
        }
    }
}

#[test]
fn test_per_phase_token_aggregation() {
    use baco::llm::metrics::OperationMetrics;
    use std::collections::HashMap;

    let mut operation_metrics: HashMap<String, OperationMetrics> = HashMap::new();
    operation_metrics.insert(
        "op1:phase1".to_string(),
        OperationMetrics {
            operation: "op1".to_string(),
            phase: "phase1".to_string(),
            requests: 2,
            successful: 2,
            failed: 0,
            tokens: 300,
            prompt_tokens: 200,
            completion_tokens: 100,
        },
    );
    operation_metrics.insert(
        "op2:phase1".to_string(),
        OperationMetrics {
            operation: "op2".to_string(),
            phase: "phase1".to_string(),
            requests: 1,
            successful: 1,
            failed: 0,
            tokens: 150,
            prompt_tokens: 100,
            completion_tokens: 50,
        },
    );
    operation_metrics.insert(
        "op3:phase2".to_string(),
        OperationMetrics {
            operation: "op3".to_string(),
            phase: "phase2".to_string(),
            requests: 1,
            successful: 1,
            failed: 0,
            tokens: 200,
            prompt_tokens: 150,
            completion_tokens: 50,
        },
    );

    let spend = ScanHealth::compute_phase_spend(&operation_metrics, None);
    assert_eq!(spend.len(), 2);

    let phase1 = spend.iter().find(|s| s.phase == "phase1").unwrap();
    assert_eq!(phase1.prompt_tokens, 300);
    assert_eq!(phase1.completion_tokens, 150);
    assert_eq!(phase1.total_tokens, 450);
    assert!(phase1.cost.is_none()); // No pricing provided

    let phase2 = spend.iter().find(|s| s.phase == "phase2").unwrap();
    assert_eq!(phase2.prompt_tokens, 150);
    assert_eq!(phase2.completion_tokens, 50);
    assert_eq!(phase2.total_tokens, 200);
    assert!(phase2.cost.is_none());
}

#[test]
fn test_cost_math_with_pricing() {
    use baco::config::ModelPricing;
    use baco::llm::metrics::OperationMetrics;
    use std::collections::HashMap;

    let mut operation_metrics: HashMap<String, OperationMetrics> = HashMap::new();
    operation_metrics.insert(
        "op1:discovery".to_string(),
        OperationMetrics {
            operation: "op1".to_string(),
            phase: "discovery".to_string(),
            requests: 1,
            successful: 1,
            failed: 0,
            tokens: 1000,
            prompt_tokens: 800,
            completion_tokens: 200,
        },
    );

    let mut pricing: HashMap<String, ModelPricing> = HashMap::new();
    pricing.insert(
        "gpt-4".to_string(),
        ModelPricing {
            prompt_per_1k: 0.03,
            completion_per_1k: 0.06,
        },
    );

    let spend = ScanHealth::compute_phase_spend(&operation_metrics, Some(&pricing));
    assert_eq!(spend.len(), 1);

    let discovery = &spend[0];
    assert_eq!(discovery.prompt_tokens, 800);
    assert_eq!(discovery.completion_tokens, 200);
    // Cost = (800/1000) * 0.03 + (200/1000) * 0.06 = 0.024 + 0.012 = 0.036
    assert!((discovery.cost.unwrap() - 0.036).abs() < 0.001);
}

#[test]
fn test_empty_pricing_no_cost() {
    use baco::llm::metrics::OperationMetrics;
    use std::collections::HashMap;

    let mut operation_metrics: HashMap<String, OperationMetrics> = HashMap::new();
    operation_metrics.insert(
        "op1:verification".to_string(),
        OperationMetrics {
            operation: "op1".to_string(),
            phase: "verification".to_string(),
            requests: 1,
            successful: 1,
            failed: 0,
            tokens: 500,
            prompt_tokens: 400,
            completion_tokens: 100,
        },
    );

    let spend = ScanHealth::compute_phase_spend(&operation_metrics, None);
    assert_eq!(spend.len(), 1);
    assert!(spend[0].cost.is_none()); // Empty pricing = no cost
    assert_eq!(spend[0].total_tokens, 500); // Tokens still reported
}

#[test]
fn test_summary_method_output_contains_per_phase_lines() {
    use baco::llm::metrics::OperationMetrics;
    use std::collections::HashMap;

    let mut operation_metrics: HashMap<String, OperationMetrics> = HashMap::new();
    operation_metrics.insert(
        "op1:llm_static_analysis".to_string(),
        OperationMetrics {
            operation: "op1".to_string(),
            phase: "LlmStaticAnalysis".to_string(),
            requests: 2,
            successful: 2,
            failed: 0,
            tokens: 1000,
            prompt_tokens: 700,
            completion_tokens: 300,
        },
    );
    operation_metrics.insert(
        "op2:llm_discovery".to_string(),
        OperationMetrics {
            operation: "op2".to_string(),
            phase: "LlmDiscovery".to_string(),
            requests: 1,
            successful: 1,
            failed: 0,
            tokens: 800,
            prompt_tokens: 600,
            completion_tokens: 200,
        },
    );

    let spend = ScanHealth::compute_phase_spend(&operation_metrics, None);
    assert_eq!(spend.len(), 2);

    // Verify per-phase lines are present
    let has_static = spend.iter().any(|s| s.phase == "LlmStaticAnalysis");
    let has_discovery = spend.iter().any(|s| s.phase == "LlmDiscovery");
    assert!(has_static);
    assert!(has_discovery);
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

#[test]
fn test_migrated_scan_health_default() {
    let health = baco::scan_health::ScanHealth::default();
    assert!(health.phase_status.is_empty());
    assert_eq!(health.files.indexed, 0);
    assert_eq!(health.total_tokens, 0);
}

#[test]
fn test_migrated_record_phase_run() {
    use baco::checkpoint::ScanPhase;
    let mut health = baco::scan_health::ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    assert_eq!(health.phase_status.len(), 1);
    assert!(matches!(
        health.phase_status[0].status,
        baco::scan_health::PhaseStatusKind::Run
    ));
    assert_eq!(health.phase_status[0].phase, "Indexing");
}

#[test]
fn test_migrated_record_phase_skipped() {
    use baco::checkpoint::ScanPhase;
    let mut health = baco::scan_health::ScanHealth::new();
    health.record_phase_skipped(
        &ScanPhase::LlmDiscovery,
        "incomplete llm.phases.discovery config",
    );
    assert_eq!(health.phase_status.len(), 1);
    assert!(matches!(
        health.phase_status[0].status,
        baco::scan_health::PhaseStatusKind::Skipped
    ));
    assert_eq!(
        health.phase_status[0].reason,
        Some("incomplete llm.phases.discovery config".to_string())
    );
}

#[test]
fn test_migrated_file_counters() {
    let mut health = baco::scan_health::ScanHealth::new();
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
fn test_migrated_llm_outcomes() {
    use baco::scan_health::LlmOutcomeClass;
    let mut health = baco::scan_health::ScanHealth::new();
    health.record_llm_outcome(&LlmOutcomeClass::Ok);
    health.record_llm_outcome(&LlmOutcomeClass::Ok);
    health.record_llm_outcome(&LlmOutcomeClass::AuthFailure);

    assert_eq!(health.llm_outcomes.get("ok"), Some(&2));
    assert_eq!(health.llm_outcomes.get("auth_failure"), Some(&1));
}

#[test]
fn test_migrated_token_recording() {
    use baco::checkpoint::ScanPhase;
    let mut health = baco::scan_health::ScanHealth::new();
    health.record_tokens(&ScanPhase::LlmDiscovery, 100, 50);
    health.record_tokens(&ScanPhase::LlmVerification, 200, 100);

    assert_eq!(health.total_tokens, 450);
    assert_eq!(health.tokens_by_phase.len(), 2);
    assert_eq!(health.tokens_by_phase[0].total_tokens, 150);
    assert_eq!(health.tokens_by_phase[1].total_tokens, 300);
}

#[test]
fn test_migrated_budget_status() {
    let mut health = baco::scan_health::ScanHealth::new();
    health.set_budget(Some(1000), 250);

    assert_eq!(health.budget.cap_maybe, Some(1000));
    assert_eq!(health.budget.used, 250);
    assert!((health.budget.pct_of_cap.unwrap() - 25.0).abs() < 0.01);
}

#[test]
fn test_migrated_all_llm_phases_skipped() {
    use baco::checkpoint::ScanPhase;
    let mut health = baco::scan_health::ScanHealth::new();
    health.record_phase_skipped(&ScanPhase::LlmStaticAnalysis, "no API key");
    health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
    health.record_phase_skipped(&ScanPhase::LlmVerification, "no API key");
    health.record_phase_skipped(&ScanPhase::SecurityAgentVerification, "no API key");

    assert!(health.all_llm_phases_skipped());
}

#[test]
fn test_migrated_blind_marker() {
    use baco::checkpoint::ScanPhase;
    let mut health = baco::scan_health::ScanHealth::new();
    assert!(health.blind_marker().is_none());

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
fn test_migrated_summary() {
    use baco::checkpoint::ScanPhase;
    let mut health = baco::scan_health::ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
    health.set_indexed(50);
    health.set_analyzed(40);
    health.set_llm_counts(0, 0);

    let summary = health.summary();
    assert!(summary.contains("phases: 1 run, 1 skipped"));
    assert!(summary.contains("files: 50 indexed, 40 analyzed"));
    assert!(summary.contains("llm: 0/0 ok/failed"));
}

#[test]
fn test_migrated_serialization() {
    use baco::checkpoint::ScanPhase;
    let mut health = baco::scan_health::ScanHealth::new();
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_skipped(&ScanPhase::LlmDiscovery, "no API key");
    health.set_indexed(100);
    health.set_llm_counts(5, 2);

    let json = serde_json::to_string(&health).unwrap();
    let parsed: baco::scan_health::ScanHealth = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.phase_status.len(), 2);
    assert_eq!(parsed.files.indexed, 100);
    assert_eq!(parsed.llm_ok, 5);
    assert_eq!(parsed.llm_failed, 2);
}
// ============================================================================
// phase_name function tests (0 refs - pure function coverage)
// ============================================================================

#[test]
fn test_phase_name_indexing() {
    use baco::scan_health::phase_name;
    assert_eq!(phase_name(&ScanPhase::Indexing), "Indexing");
}

#[test]
fn test_phase_name_semgrep() {
    use baco::scan_health::phase_name;
    assert_eq!(phase_name(&ScanPhase::Semgrep), "Semgrep");
}

#[test]
fn test_phase_name_llm_phases() {
    use baco::scan_health::phase_name;
    assert_eq!(
        phase_name(&ScanPhase::LlmStaticAnalysis),
        "LlmStaticAnalysis"
    );
    assert_eq!(phase_name(&ScanPhase::LlmDiscovery), "LlmDiscovery");
    assert_eq!(phase_name(&ScanPhase::LlmVerification), "LlmVerification");
    assert_eq!(
        phase_name(&ScanPhase::SecurityAgentVerification),
        "SecurityAgentVerification"
    );
}

// ============================================================================
// blind_marker edge case tests
// ============================================================================

#[test]
fn test_blind_marker_partial_skip_llm_ok_gt_zero() {
    // Edge case: some LLM phases skipped but llm_ok > 0 → no marker
    let mut health = ScanHealth::new();
    health.record_phase_skipped(&ScanPhase::LlmStaticAnalysis, "no API key");
    health.record_phase_run(&ScanPhase::LlmDiscovery);
    health.record_phase_skipped(&ScanPhase::LlmVerification, "no API key");
    health.record_phase_skipped(&ScanPhase::SecurityAgentVerification, "no API key");
    health.set_llm_counts(5, 0);

    assert!(health.blind_marker().is_none());
}

#[test]
fn test_blind_marker_empty_health() {
    // Edge case: completely empty health report
    let health = ScanHealth::new();
    assert!(health.blind_marker().is_none());
}
