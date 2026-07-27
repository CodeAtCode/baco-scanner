//! Unit tests for scanner pipeline orchestration and resumption.
//!
//! Tests cover PhaseGraph, Orchestrator, CheckpointManager, ScanCheckpoint,
//! and CheckpointConfig from src/scanner/pipeline/.

use baco::checkpoint::ScanPhase;
use baco::config::ScannerConfig;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::llm_metrics::LlmMetricsTracker;
use baco::scanner::{CheckpointManager, Orchestrator, PhaseGraph, ScanCheckpoint};
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// Test Fixtures
// ============================================================================

fn create_test_finding(title: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        description: format!("Test finding: {}", title),
        severity: Severity::Medium,
        confidence_score: 0.7,
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("test code".to_string()),
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

fn get_temp_checkpoint_path(suffix: &str) -> PathBuf {
    let temp_dir = TempDir::new().unwrap();
    temp_dir.path().join(suffix)
}

// ============================================================================
// PhaseGraph Construction Tests
// ============================================================================

#[test]
fn test_phase_graph_new_creates_all_phases() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    assert!(!phases.is_empty());
}

#[test]
fn test_phase_graph_first_phase_is_indexing() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    assert_eq!(phases[0], ScanPhase::Indexing);
}

#[test]
fn test_phase_graph_last_phase_is_variant_search() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    assert_eq!(phases[phases.len() - 1], ScanPhase::VariantSearch);
}

#[test]
fn test_phase_graph_has_expected_phase_count() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    assert!(phases.len() >= 19, "Expected at least 19 phases");
}

// ============================================================================
// PhaseMetadata Tests
// ============================================================================

#[test]
fn test_get_metadata_returns_some_for_valid_phase() {
    let graph = PhaseGraph::new();
    let meta = graph.get_metadata(&ScanPhase::Indexing);

    assert!(meta.is_some());
}

#[test]
fn test_phase_metadata_contains_expected_fields() {
    let graph = PhaseGraph::new();
    let meta = graph.get_metadata(&ScanPhase::Semgrep).unwrap();

    assert!(!meta.display_name.is_empty());
    assert!(!meta.description.is_empty());
    assert!(meta.phase_number > 0);
    assert!(meta.total_phases > 0);
}

#[test]
fn test_phase_metadata_phase_number_matches_position() {
    let graph = PhaseGraph::new();

    for (idx, phase) in graph.phases().iter().enumerate() {
        let meta = graph.get_metadata(phase).unwrap();
        assert_eq!(meta.phase_number, (idx + 1) as u8);
    }
}

#[test]
fn test_all_phases_have_metadata() {
    let graph = PhaseGraph::new();

    for phase in graph.phases() {
        let meta = graph.get_metadata(phase);
        assert!(meta.is_some(), "Missing metadata for {:?}", phase);
    }
}

// ============================================================================
// Phase Navigation Tests
// ============================================================================

#[test]
fn test_next_phase_returns_none_for_last_phase() {
    let graph = PhaseGraph::new();
    let result = graph.next_phase(&ScanPhase::VariantSearch);

    assert!(result.is_none());
}

#[test]
fn test_next_phase_returns_none_for_complete_phase() {
    let graph = PhaseGraph::new();
    let result = graph.next_phase(&ScanPhase::Complete);

    assert!(result.is_none());
}

#[test]
fn test_previous_phase_returns_none_for_first_phase() {
    let graph = PhaseGraph::new();
    let result = graph.previous_phase(&ScanPhase::Indexing);

    assert!(result.is_none());
}

#[test]
fn test_next_phase_chain_from_indexing() {
    let graph = PhaseGraph::new();

    let semgrep = graph.next_phase(&ScanPhase::Indexing);
    assert!(semgrep.is_some());
    assert_eq!(semgrep.unwrap(), &ScanPhase::Semgrep);
}

#[test]
fn test_previous_phase_chain_from_variant_search() {
    let graph = PhaseGraph::new();

    let poc = graph.previous_phase(&ScanPhase::VariantSearch);
    assert!(poc.is_some());
    assert_eq!(poc.unwrap(), &ScanPhase::PocCompiler);
}

// ============================================================================
// Phase Enablement Tests
// ============================================================================

#[test]
fn test_core_phases_are_always_enabled() {
    let config = ScannerConfig::default();
    let graph = PhaseGraph::new();

    assert!(graph.is_phase_enabled(&ScanPhase::Indexing, &config));
    assert!(graph.is_phase_enabled(&ScanPhase::Semgrep, &config));
    assert!(graph.is_phase_enabled(&ScanPhase::LlmDiscovery, &config));
}

#[test]
fn test_confidence_scoring_respects_config() {
    let mut config = ScannerConfig::default();
    config.scanner.performance.enable_confidence_refinement = false;
    let graph = PhaseGraph::new();

    assert!(!graph.is_phase_enabled(&ScanPhase::ConfidenceScoring, &config));
}

#[test]
fn test_threat_modeling_respects_config() {
    let mut config = ScannerConfig::default();
    config.scanner.performance.enable_threat_modeling = true;
    let graph = PhaseGraph::new();

    assert!(graph.is_phase_enabled(&ScanPhase::ThreatModeling, &config));
}

#[test]
fn test_auto_patching_respects_config() {
    let mut config = ScannerConfig::default();
    config.scanner.performance.enable_auto_patching = false;
    let graph = PhaseGraph::new();

    assert!(!graph.is_phase_enabled(&ScanPhase::AutoPatching, &config));
}

// ============================================================================
// Orchestrator Tests
// ============================================================================

#[test]
fn test_orchestrator_new_creates_instance() {
    let config = ScannerConfig::default();
    let orchestrator = Orchestrator::new(&config);

    assert!(!orchestrator.phase_graph().phases().is_empty());
}

#[test]
fn test_orchestrator_phase_graph_access() {
    let config = ScannerConfig::default();
    let orchestrator = Orchestrator::new(&config);
    let phase_graph = orchestrator.phase_graph();

    assert!(!phase_graph.phases().is_empty());
}

#[test]
fn test_orchestrator_config_access() {
    let config = ScannerConfig::default();
    let orchestrator = Orchestrator::new(&config);
    let retrieved_config = orchestrator.config();

    assert_eq!(
        retrieved_config.scanner.commit_lookback_days,
        config.scanner.commit_lookback_days
    );
}

#[test]
fn test_orchestrator_metadata_access() {
    let config = ScannerConfig::default();
    let orchestrator = Orchestrator::new(&config);
    let phase_graph = orchestrator.phase_graph();
    let meta = phase_graph.get_metadata(&ScanPhase::Indexing);

    assert!(meta.is_some());
    assert_eq!(meta.unwrap().display_name, "Indexing");
}

// ============================================================================
// CheckpointManager Tests
// ============================================================================

#[tokio::test]
async fn test_checkpoint_manager_new() {
    let path = get_temp_checkpoint_path("test_new.json");
    let manager = CheckpointManager::new(path.clone());

    assert!(!manager.exists());
}

#[tokio::test]
async fn test_checkpoint_manager_exists_false_when_no_file() {
    let path = get_temp_checkpoint_path("test_exists.json");
    let manager = CheckpointManager::new(path);

    assert!(!manager.exists());
}

#[tokio::test]
async fn test_checkpoint_manager_save_creates_file() {
    let path = get_temp_checkpoint_path("test_save.json");
    let manager = CheckpointManager::new(path.clone());
    let metrics = LlmMetricsTracker::new();

    let _: Result<(), String> = manager.save(&ScanPhase::Indexing, &[], &[], &metrics).await;

    assert!(manager.exists());
}

#[tokio::test]
async fn test_checkpoint_manager_load_returns_none_when_missing() {
    let path = get_temp_checkpoint_path("test_load_none.json");
    let manager = CheckpointManager::new(path);

    let result: Option<ScanCheckpoint> = manager.load().await;

    assert!(result.is_none());
}

#[tokio::test]
async fn test_checkpoint_manager_save_and_load_roundtrip() {
    let path = get_temp_checkpoint_path("test_roundtrip.json");
    let manager = CheckpointManager::new(path.clone());
    let finding = create_test_finding("Roundtrip");
    let files = vec!["file1.rs".to_string(), "file2.rs".to_string()];
    let metrics = LlmMetricsTracker::new();

    let _: Result<(), String> = manager
        .save(&ScanPhase::Semgrep, &[finding], &files, &metrics)
        .await;

    let loaded = {
        let x: Option<ScanCheckpoint> = manager.load().await;
        x.unwrap()
    };

    assert_eq!(loaded.last_completed_phase, ScanPhase::Semgrep);
    assert_eq!(loaded.findings.len(), 1);
    assert_eq!(loaded.findings[0].title, "Roundtrip");
    assert_eq!(loaded.analyzed_files.len(), 2);
}

#[tokio::test]
async fn test_checkpoint_manager_last_completed_phase() {
    let path = get_temp_checkpoint_path("test_last_phase.json");
    let manager = CheckpointManager::new(path.clone());
    let metrics = LlmMetricsTracker::new();

    let _: Result<(), String> = manager
        .save(&ScanPhase::Reporting, &[], &[], &metrics)
        .await;

    let phase: Option<ScanPhase> = manager.last_completed_phase().await;

    assert!(phase.is_some());
    assert_eq!(phase.unwrap(), ScanPhase::Reporting);
}

#[tokio::test]
async fn test_checkpoint_manager_delete() {
    let path = get_temp_checkpoint_path("test_delete.json");
    let manager = CheckpointManager::new(path.clone());
    let metrics = LlmMetricsTracker::new();

    let _: Result<(), String> = manager.save(&ScanPhase::Indexing, &[], &[], &metrics).await;
    assert!(manager.exists());

    let result: Result<(), String> = manager.delete();

    assert!(result.is_ok());
    assert!(!manager.exists());
}

#[tokio::test]
async fn test_checkpoint_manager_delete_nonexistent_file() {
    let path = get_temp_checkpoint_path("test_delete_missing.json");
    let manager = CheckpointManager::new(path);

    let result: Result<(), String> = manager.delete();

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_checkpoint_manager_save_creates_parent_directory() {
    let temp_dir = TempDir::new().unwrap();
    let nested_path = temp_dir.path().join("nested/deep/checkpoint.json");
    let manager = CheckpointManager::new(nested_path.clone());
    let metrics = LlmMetricsTracker::new();

    let _: Result<(), String> = manager.save(&ScanPhase::Indexing, &[], &[], &metrics).await;

    assert!(nested_path.exists());
}

#[tokio::test]
async fn test_checkpoint_manager_save_with_empty_findings() {
    let path = get_temp_checkpoint_path("test_empty_findings.json");
    let manager = CheckpointManager::new(path.clone());
    let metrics = LlmMetricsTracker::new();
    let findings: Vec<VulnerabilityFinding> = vec![];
    let files: Vec<String> = vec![];

    let _: Result<(), String> = manager
        .save(&ScanPhase::Indexing, &findings, &files, &metrics)
        .await;

    let loaded = {
        let x: Option<ScanCheckpoint> = manager.load().await;
        x.unwrap()
    };
    assert!(loaded.findings.is_empty());
    assert!(loaded.analyzed_files.is_empty());
}

#[tokio::test]
async fn test_checkpoint_manager_load_invalid_json_returns_none() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("test_invalid.json");
    std::fs::write(&path, "not valid json").unwrap();
    let manager = CheckpointManager::new(path);

    let result: Option<ScanCheckpoint> = manager.load().await;

    assert!(result.is_none());
}

// ============================================================================
// ScanCheckpoint Serialization Tests
// ============================================================================

#[test]
fn test_scan_checkpoint_serialization() {
    let checkpoint = ScanCheckpoint {
        last_completed_phase: ScanPhase::LlmStaticAnalysis,
        findings: vec![create_test_finding("Serialize")],
        analyzed_files: vec!["test.rs".to_string()],
        timestamp: "2024-01-01T00:00:00Z".to_string(),
    };

    let json = serde_json::to_string(&checkpoint).unwrap();

    assert!(json.contains("last_completed_phase"));
    assert!(json.contains("LlmStaticAnalysis"));
    assert!(json.contains("findings"));
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[tokio::test]
async fn test_checkpoint_manager_save_all_phases() {
    let phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmDiscovery,
        ScanPhase::Reporting,
        ScanPhase::ThreatModeling,
        ScanPhase::Complete,
    ];

    for phase in phases {
        let path = get_temp_checkpoint_path(&format!("test_{:?}.json", phase));
        let manager = CheckpointManager::new(path.clone());
        let metrics = LlmMetricsTracker::new();

        let _: Result<(), String> = manager.save(&phase, &[], &[], &metrics).await;

        assert!(manager.exists());

        let loaded = {
            let x: Option<ScanCheckpoint> = manager.load().await;
            x.unwrap()
        };
        assert_eq!(loaded.last_completed_phase, phase);
    }
}

#[test]
fn test_phase_graph_phases_slice_is_immutable() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    let count = phases.len();
    assert!(count > 0);

    for phase in phases {
        let _ = phase;
    }
}

#[test]
fn test_orchestrator_lifecycle() {
    let config = ScannerConfig::default();
    let orchestrator = Orchestrator::new(&config);

    let _graph = orchestrator.phase_graph();
    let _config = orchestrator.config();
    let _phases = orchestrator.phase_graph().phases();
    let _meta = orchestrator
        .phase_graph()
        .get_metadata(&ScanPhase::Indexing);
}

#[tokio::test]
async fn test_checkpoint_manager_multiple_saves_overwrite() {
    let path = get_temp_checkpoint_path("test_overwrite.json");
    let manager = CheckpointManager::new(path.clone());
    let metrics = LlmMetricsTracker::new();

    let _: Result<(), String> = manager.save(&ScanPhase::Indexing, &[], &[], &metrics).await;
    let first = {
        let x: Option<ScanCheckpoint> = manager.load().await;
        x.unwrap()
    };

    let _: Result<(), String> = manager.save(&ScanPhase::Semgrep, &[], &[], &metrics).await;
    let second = {
        let x: Option<ScanCheckpoint> = manager.load().await;
        x.unwrap()
    };

    assert_eq!(first.last_completed_phase, ScanPhase::Indexing);
    assert_eq!(second.last_completed_phase, ScanPhase::Semgrep);
}

#[test]
fn test_phase_metadata_display_name_unique() {
    let graph = PhaseGraph::new();
    let mut names: Vec<String> = Vec::new();

    for phase in graph.phases() {
        let meta = graph.get_metadata(phase).unwrap();
        names.push(meta.display_name.clone());
    }

    names.sort();
    names.dedup();

    assert_eq!(
        names.len(),
        graph.phases().len(),
        "Found duplicate display names"
    );
}
