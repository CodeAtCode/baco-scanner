//! Unit tests for checkpoint save/load operations
//!
//! Tests cover checkpoint creation, serialization, validation, and the
//! save_checkpoint/load_checkpoint_findings functions.

use baco::checkpoint::{Checkpoint, ScanPhase};
use baco::findings::{Severity, VulnerabilityFinding};
use std::fs;
use std::path::Path;

// Shared test data for phase transition tests (mirrors src/scanner/checkpoint.rs)
const PHASE_TRANSITION_TEST_CASES: &[(ScanPhase, ScanPhase)] = &[
    // Parallel phases
    (ScanPhase::Indexing, ScanPhase::Semgrep),
    (ScanPhase::Semgrep, ScanPhase::LlmStaticAnalysis),
    (ScanPhase::LlmStaticAnalysis, ScanPhase::CweRouting),
    // Sequential phases
    (ScanPhase::CweRouting, ScanPhase::LlmDiscovery),
    (ScanPhase::LlmDiscovery, ScanPhase::LlmVerification),
    (
        ScanPhase::LlmVerification,
        ScanPhase::SecurityAgentVerification,
    ),
    (
        ScanPhase::SecurityAgentVerification,
        ScanPhase::TicketCrossRef,
    ),
    (ScanPhase::TicketCrossRef, ScanPhase::GitAnalysis),
    (ScanPhase::GitAnalysis, ScanPhase::CrossFileAnalysis),
    (ScanPhase::CrossFileAnalysis, ScanPhase::ConfidenceScoring),
    (ScanPhase::ConfidenceScoring, ScanPhase::AiAggregation),
    (ScanPhase::AiAggregation, ScanPhase::ThreatModeling),
    (ScanPhase::ThreatModeling, ScanPhase::RootCauseDedup),
    (ScanPhase::RootCauseDedup, ScanPhase::MultiVerifier),
    (ScanPhase::MultiVerifier, ScanPhase::AutoPatching),
    (ScanPhase::AutoPatching, ScanPhase::CveBootstrap),
    (ScanPhase::CveBootstrap, ScanPhase::PocCompiler),
    (ScanPhase::PocCompiler, ScanPhase::VariantSearch),
    (ScanPhase::VariantSearch, ScanPhase::Reporting),
    (ScanPhase::Reporting, ScanPhase::Complete),
    // Orphaned phases
    (ScanPhase::CpgSlice, ScanPhase::CweRouting),
    (ScanPhase::Hunt, ScanPhase::LlmDiscovery),
    (ScanPhase::Validate, ScanPhase::LlmDiscovery),
    (ScanPhase::IndependentVerify, ScanPhase::LlmDiscovery),
    (ScanPhase::ExploitSynth, ScanPhase::LlmDiscovery),
    (ScanPhase::RuleSynthesis, ScanPhase::Complete),
    // Terminal states
    (ScanPhase::Complete, ScanPhase::Indexing),
    (ScanPhase::Error, ScanPhase::Indexing),
];

// ============================================================================
// Test Fixtures
// ============================================================================

fn create_test_checkpoint() -> Checkpoint {
    Checkpoint::new("test-scan-123", "/tmp/test-project", chrono::Utc::now())
}

fn create_test_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-id".to_string(),
        title: "Test Finding".to_string(),
        description: "A test vulnerability".to_string(),
        severity: Severity::High,
        confidence_score: 0.85,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/vulnerable.c".to_string(),
        line_number: Some(42),
        code_snippet: Some("printf(user_input)".to_string()),
        diff_hunk: None,
        recommendation: Some("Use sanitized input".to_string()),
        code_location: Some("src/vulnerable.c:42".to_string()),
        already_reported: false,
        sources: vec!["semgrep".to_string()],
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

fn get_temp_path(suffix: &str) -> String {
    format!("/tmp/baco_checkpoint_test_{}", suffix)
}

// ============================================================================
// Checkpoint::new() Tests
// ============================================================================

#[test]
fn test_checkpoint_new_creates_valid_checkpoint() {
    let now = chrono::Utc::now();
    let checkpoint = Checkpoint::new("scan-456", "/test/path", now);

    assert_eq!(checkpoint.scan_id, "scan-456");
    assert_eq!(checkpoint.project_path, "/test/path");
    assert_eq!(checkpoint.started_at, now);
    assert_eq!(checkpoint.current_phase, ScanPhase::Indexing);
    assert!(checkpoint.completed_phases.is_empty());
    assert!(checkpoint.findings_so_far.is_empty());
    assert_eq!(checkpoint.file_count, 0);
    assert!(checkpoint.analyzed_files.is_empty());
}

#[test]
fn test_checkpoint_new_empty_strings() {
    let checkpoint = Checkpoint::new("", "", chrono::Utc::now());

    assert_eq!(checkpoint.scan_id, "");
    assert_eq!(checkpoint.project_path, "");
    assert_eq!(checkpoint.current_phase, ScanPhase::Indexing);
}

// ============================================================================
// Checkpoint::save() Tests
// ============================================================================

#[test]
fn test_checkpoint_save_creates_file() {
    let checkpoint = create_test_checkpoint();
    let temp_path = get_temp_path("save_creates");

    let result = checkpoint.save(&temp_path);
    assert!(result.is_ok());
    assert!(Path::new(&temp_path).exists());

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_save_creates_parent_directories() {
    let checkpoint = create_test_checkpoint();
    let temp_path = get_temp_path("save_nested/nested/dir/checkpoint.json");

    let result = checkpoint.save(&temp_path);
    assert!(result.is_ok());
    assert!(Path::new(&temp_path).exists());

    let _ = fs::remove_file(&temp_path);
    let _ = fs::remove_dir_all(Path::new(&temp_path).parent().unwrap());
}

#[test]
fn test_checkpoint_save_valid_json() {
    let checkpoint = create_test_checkpoint();
    let temp_path = get_temp_path("save_valid_json");

    checkpoint.save(&temp_path).unwrap();

    let content = fs::read_to_string(&temp_path).unwrap();
    let json_value: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json_value["scan_id"], "test-scan-123");
    assert_eq!(json_value["project_path"], "/tmp/test-project");
    assert!(json_value.get("started_at").is_some());

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_save_with_findings() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.findings_so_far.push(create_test_finding());

    let temp_path = get_temp_path("save_with_findings");
    checkpoint.save(&temp_path).unwrap();

    let content = fs::read_to_string(&temp_path).unwrap();
    let json_value: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json_value["findings_so_far"][0]["id"], "test-finding-id");

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_save_with_analyzed_files() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.analyzed_files.push("src/main.rs".to_string());
    checkpoint.analyzed_files.push("src/lib.rs".to_string());

    let temp_path = get_temp_path("save_analyzed_files");
    checkpoint.save(&temp_path).unwrap();

    let loaded = Checkpoint::load(&temp_path).unwrap();
    assert_eq!(loaded.analyzed_files.len(), 2);

    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// Checkpoint::load() Tests
// ============================================================================

#[test]
fn test_checkpoint_load_valid_file() {
    let checkpoint = create_test_checkpoint();
    let temp_path = get_temp_path("load_valid");

    checkpoint.save(&temp_path).unwrap();
    let loaded = Checkpoint::load(&temp_path).unwrap();

    assert_eq!(checkpoint.scan_id, loaded.scan_id);
    assert_eq!(checkpoint.project_path, loaded.project_path);
    assert_eq!(checkpoint.current_phase, loaded.current_phase);

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_load_nonexistent_file() {
    let result = Checkpoint::load("/nonexistent/path/checkpoint.json");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("read"));
}

#[test]
fn test_checkpoint_load_invalid_json() {
    let temp_path = get_temp_path("load_invalid_json");
    fs::write(&temp_path, "not valid json {").unwrap();

    let result = Checkpoint::load(&temp_path);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("parse"));

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_load_empty_file() {
    let temp_path = get_temp_path("load_empty");
    fs::write(&temp_path, "").unwrap();

    let result = Checkpoint::load(&temp_path);
    assert!(result.is_err());

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_load_missing_scan_id() {
    let temp_path = get_temp_path("load_missing_scan_id");
    let corrupted = r#"{"scan_id":"","project_path":"test","started_at":"2024-01-01T00:00:00Z","current_phase":"Indexing","completed_phases":[],"findings_so_far":[],"file_count":0,"analyzed_files":[]}"#;
    fs::write(&temp_path, corrupted).unwrap();

    let result = Checkpoint::load(&temp_path);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("scan_id"));

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_load_missing_project_path() {
    let temp_path = get_temp_path("load_missing_project_path");
    let corrupted = r#"{"scan_id":"test123","project_path":"","started_at":"2024-01-01T00:00:00Z","current_phase":"Indexing","completed_phases":[],"findings_so_far":[],"file_count":0,"analyzed_files":[]}"#;
    fs::write(&temp_path, corrupted).unwrap();

    let result = Checkpoint::load(&temp_path);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("project_path"));

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_load_with_findings() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.findings_so_far.push(create_test_finding());

    let temp_path = get_temp_path("load_with_findings");
    checkpoint.save(&temp_path).unwrap();

    let loaded = Checkpoint::load(&temp_path).unwrap();
    assert_eq!(loaded.findings_so_far.len(), 1);
    assert_eq!(loaded.findings_so_far[0].id, "test-finding-id");

    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// Checkpoint::validate() Tests
// ============================================================================

#[test]
fn test_checkpoint_validate_valid() {
    let checkpoint = create_test_checkpoint();
    let result = checkpoint.validate();
    assert!(result.is_ok());
}

#[test]
fn test_checkpoint_validate_empty_scan_id() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.scan_id = String::new();

    let result = checkpoint.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("scan_id"));
}

#[test]
fn test_checkpoint_validate_empty_project_path() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.project_path = String::new();

    let result = checkpoint.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("project_path"));
}

#[test]
fn test_checkpoint_validate_both_empty() {
    let checkpoint = Checkpoint::new("", "", chrono::Utc::now());

    let result = checkpoint.validate();
    assert!(result.is_err());
    // Should fail on scan_id first
    assert!(result.unwrap_err().contains("scan_id"));
}

// ============================================================================
// Checkpoint::resume_from() Tests
// ============================================================================

#[test]
fn test_checkpoint_resume_from_indexing() {
    let checkpoint = create_test_checkpoint();
    let temp_path = get_temp_path("resume_indexing");
    checkpoint.save(&temp_path).unwrap();

    let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
    assert_eq!(next_phase, ScanPhase::Semgrep);

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_resume_from_semgrep() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.current_phase = ScanPhase::Semgrep;

    let temp_path = get_temp_path("resume_semgrep");
    checkpoint.save(&temp_path).unwrap();

    let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
    assert_eq!(next_phase, ScanPhase::LlmStaticAnalysis);

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_resume_from_complete() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.current_phase = ScanPhase::Complete;

    let temp_path = get_temp_path("resume_complete");
    checkpoint.save(&temp_path).unwrap();

    let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
    assert_eq!(next_phase, ScanPhase::Indexing);

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_resume_from_error() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.current_phase = ScanPhase::Error;

    let temp_path = get_temp_path("resume_error");
    checkpoint.save(&temp_path).unwrap();

    let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
    assert_eq!(next_phase, ScanPhase::Indexing);

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_resume_from_all_phases() {
    for (current_phase, expected_next) in PHASE_TRANSITION_TEST_CASES {
        let mut checkpoint = create_test_checkpoint();
        checkpoint.current_phase = current_phase.clone();

        let temp_path = get_temp_path(&format!("resume_{:?}", current_phase));
        checkpoint.save(&temp_path).unwrap();

        let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
        assert_eq!(
            next_phase,
            expected_next.clone(),
            "Resume from {:?} should return {:?}",
            current_phase,
            expected_next
        );

        let _ = fs::remove_file(&temp_path);
    }
}

#[test]
fn test_checkpoint_resume_from_invalid_file() {
    let temp_path = get_temp_path("resume_invalid");
    fs::write(&temp_path, "not json at all").unwrap();

    let result = Checkpoint::resume_from(&temp_path);
    assert!(result.is_err());

    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// Checkpoint::format_phase() Tests
// ============================================================================

#[test]
fn test_checkpoint_format_phase_indexing() {
    let checkpoint = create_test_checkpoint();
    let formatted = checkpoint.format_phase();
    assert!(formatted.contains("Indexing"));
}

#[test]
fn test_checkpoint_format_phase_complete() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.current_phase = ScanPhase::Complete;
    let formatted = checkpoint.format_phase();
    assert!(formatted.contains("Complete"));
}

#[test]
fn test_checkpoint_format_phase_error() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.current_phase = ScanPhase::Error;
    let formatted = checkpoint.format_phase();
    assert!(formatted.contains("Error"));
}

// ============================================================================
// Checkpoint Clone/Copy Tests
// ============================================================================

#[test]
fn test_checkpoint_clone() {
    let checkpoint = create_test_checkpoint();
    let cloned = checkpoint.clone();

    assert_eq!(checkpoint.scan_id, cloned.scan_id);
    assert_eq!(checkpoint.project_path, cloned.project_path);
    assert_eq!(checkpoint.current_phase, cloned.current_phase);
    assert_eq!(checkpoint.file_count, cloned.file_count);
}

// ============================================================================
// Checkpoint Serialization Tests
// ============================================================================

#[test]
fn test_checkpoint_json_roundtrip() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.file_count = 150;
    checkpoint.current_phase = ScanPhase::Semgrep;
    checkpoint.completed_phases.push(ScanPhase::Indexing);
    checkpoint.findings_so_far.push(create_test_finding());

    let temp_path = get_temp_path("json_roundtrip");
    checkpoint.save(&temp_path).unwrap();

    let loaded = Checkpoint::load(&temp_path).unwrap();

    assert_eq!(checkpoint.scan_id, loaded.scan_id);
    assert_eq!(checkpoint.file_count, loaded.file_count);
    assert_eq!(checkpoint.current_phase, loaded.current_phase);
    assert_eq!(checkpoint.completed_phases, loaded.completed_phases);
    assert_eq!(
        checkpoint.findings_so_far.len(),
        loaded.findings_so_far.len()
    );

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_serialization_with_all_phases() {
    let mut checkpoint = create_test_checkpoint();
    checkpoint.completed_phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
    ];

    let temp_path = get_temp_path("all_phases");
    checkpoint.save(&temp_path).unwrap();

    let loaded = Checkpoint::load(&temp_path).unwrap();
    assert_eq!(loaded.completed_phases.len(), 3);

    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// ScanPhase Tests
// ============================================================================

#[test]
fn test_scan_phase_equality() {
    assert_eq!(ScanPhase::Indexing, ScanPhase::Indexing);
    assert_ne!(ScanPhase::Indexing, ScanPhase::Semgrep);
    assert_eq!(ScanPhase::Complete, ScanPhase::Complete);
}

#[test]
fn test_scan_phase_debug() {
    let debug = format!("{:?}", ScanPhase::LlmDiscovery);
    assert_eq!(debug, "LlmDiscovery");
}

#[test]
fn test_scan_phase_all_variants_exist() {
    // Verify all phase variants can be created
    let _ = ScanPhase::Indexing;
    let _ = ScanPhase::Semgrep;
    let _ = ScanPhase::LlmStaticAnalysis;
    let _ = ScanPhase::LlmDiscovery;
    let _ = ScanPhase::LlmVerification;
    let _ = ScanPhase::TicketCrossRef;
    let _ = ScanPhase::GitAnalysis;
    let _ = ScanPhase::CrossFileAnalysis;
    let _ = ScanPhase::ConfidenceScoring;
    let _ = ScanPhase::AiAggregation;
    let _ = ScanPhase::Reporting;
    let _ = ScanPhase::ThreatModeling;
    let _ = ScanPhase::RootCauseDedup;
    let _ = ScanPhase::MultiVerifier;
    let _ = ScanPhase::AutoPatching;
    let _ = ScanPhase::CveBootstrap;
    let _ = ScanPhase::PocCompiler;
    let _ = ScanPhase::VariantSearch;
    let _ = ScanPhase::SecurityAgentVerification;
    let _ = ScanPhase::Complete;
    let _ = ScanPhase::Error;
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_checkpoint_full_lifecycle() {
    // Create checkpoint
    let mut checkpoint = create_test_checkpoint();
    checkpoint.file_count = 100;
    checkpoint.analyzed_files.push("src/main.rs".to_string());

    // Save
    let temp_path = get_temp_path("lifecycle");
    checkpoint.save(&temp_path).unwrap();

    // Load
    let loaded = Checkpoint::load(&temp_path).unwrap();

    // Verify
    assert_eq!(loaded.scan_id, checkpoint.scan_id);
    assert_eq!(loaded.file_count, 100);
    assert_eq!(loaded.analyzed_files.len(), 1);

    // Modify and save again
    let mut checkpoint2 = loaded;
    checkpoint2.current_phase = ScanPhase::Semgrep;
    checkpoint2.completed_phases.push(ScanPhase::Indexing);
    checkpoint2.save(&temp_path).unwrap();

    // Load again
    let loaded2 = Checkpoint::load(&temp_path).unwrap();
    assert_eq!(loaded2.current_phase, ScanPhase::Semgrep);
    assert_eq!(loaded2.completed_phases.len(), 1);

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn test_checkpoint_multiple_save_load_cycles() {
    let mut checkpoint = create_test_checkpoint();
    let temp_path = get_temp_path("cycles");

    for i in 0..5 {
        checkpoint.file_count = i * 10;
        checkpoint.save(&temp_path).unwrap();

        let loaded = Checkpoint::load(&temp_path).unwrap();
        assert_eq!(loaded.file_count, i * 10);
    }

    let _ = fs::remove_file(&temp_path);
}
