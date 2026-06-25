//! Checkpoint tests (10 tests)
//!
//! Tests for checkpoint save/load, resume functionality,
//! and state persistence across scan phases.

use crate::checkpoint::{Checkpoint, ScanPhase};

use crate::phase::tests::test_fixtures::{create_complete_finding, create_test_finding};
use chrono::Utc;
use std::fs;
use tempfile::TempDir;

/// Create a minimal test finding

// ========================================================================
// CHECKPOINT TESTS (10 tests)
// ========================================================================

/// Test 4: Checkpoint save/load field integrity
#[test]
fn test_field_preservation_checkpoint_field_integrity() {
    let finding = create_complete_finding();
    let checkpoint = Checkpoint::new("integrity-test", "/tmp/integrity", Utc::now());
    let temp_path = "/tmp/test_checkpoint_integrity.json";

    let mut checkpoint_with_finding = checkpoint;
    checkpoint_with_finding.findings_so_far.push(finding.clone());
    checkpoint_with_finding.file_count = 42;
    checkpoint_with_finding.analyzed_files
        = vec!["src/main.rs".to_string(), "src/utils.rs".to_string()];
    checkpoint_with_finding.save(temp_path).unwrap();

    let loaded = Checkpoint::load(temp_path).unwrap();

    assert_eq!(loaded.file_count, 42);
    assert_eq!(loaded.analyzed_files.len(), 2);
    assert_eq!(loaded.findings_so_far.len(), 1);

    let loaded_finding = &loaded.findings_so_far[0];
    assert_eq!(loaded_finding.id, finding.id);
    assert_eq!(loaded_finding.severity, finding.severity);
    assert_eq!(loaded_finding.llm_model, finding.llm_model);

    let _ = fs::remove_file(temp_path);
}

/// Test 32: Checkpoint resume from each phase
#[test]
fn test_integration_checkpoint_resume_all_phases() {
    let test_cases = vec![
        (ScanPhase::Indexing, ScanPhase::Semgrep),
        (ScanPhase::Semgrep, ScanPhase::LlmStaticAnalysis),
        (ScanPhase::LlmStaticAnalysis, ScanPhase::LlmDiscovery),
        (ScanPhase::LlmDiscovery, ScanPhase::LlmVerification),
        (ScanPhase::LlmVerification, ScanPhase::TicketCrossRef),
        (ScanPhase::TicketCrossRef, ScanPhase::GitAnalysis),
        (ScanPhase::GitAnalysis, ScanPhase::CrossFileAnalysis),
        (ScanPhase::CrossFileAnalysis, ScanPhase::ConfidenceScoring),
        (ScanPhase::ConfidenceScoring, ScanPhase::AiAggregation),
        (ScanPhase::AiAggregation, ScanPhase::Reporting),
        (ScanPhase::VariantSearch, ScanPhase::SecurityAgentVerification),
        (ScanPhase::SecurityAgentVerification, ScanPhase::Complete),
        (ScanPhase::Reporting, ScanPhase::Indexing), // Simplified - real code goes to ThreatModeling
    ];

    for (current, expected_next) in test_cases {
        let checkpoint = Checkpoint::new("resume-test", "/tmp", Utc::now());
        let temp_path = format!("/tmp/test_resume_{:?}", current);
        let mut cp = checkpoint.clone();
        cp.current_phase = current.clone();
        cp.save(&temp_path).unwrap();

        let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
        // Note: Reporting resumes to ThreatModeling in real code, not Indexing
        if current == ScanPhase::Reporting {
            assert_eq!(next_phase, ScanPhase::ThreatModeling, "Resume from {:?} failed", current);
        } else {
            assert_eq!(next_phase, expected_next, "Resume from {:?} failed", current);
        }

        let _ = fs::remove_file(&temp_path);
    }
}

/// Test 37: Full pipeline - checkpoint persistence
#[test]
fn test_integration_checkpoint_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let checkpoint_path = temp_dir.path().join("checkpoint.json");

    let checkpoint = Checkpoint::new("persist-test", temp_dir.path().to_str().unwrap(), Utc::now());
    checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();

    // Verify file exists
    assert!(checkpoint_path.exists());

    // Load and verify
    let loaded = Checkpoint::load(checkpoint_path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.scan_id, "persist-test");
}

/// Test: Checkpoint - llm_model preservation through checkpoint save/load
#[test]
fn test_field_preservation_llm_model_checkpoint() {
    let mut finding = create_test_finding();
    finding.llm_model = Some("claude-3.5-sonnet".to_string());

    let checkpoint = Checkpoint::new("test-123", "/tmp/test", Utc::now());
    let temp_path = "/tmp/test_checkpoint_llm_model.json";

    // Simulate adding finding to checkpoint
    let mut checkpoint_with_finding = checkpoint.clone();
    checkpoint_with_finding.findings_so_far.push(finding.clone());
    checkpoint_with_finding.save(temp_path).unwrap();

    let loaded = Checkpoint::load(temp_path).unwrap();
    assert_eq!(loaded.findings_so_far.len(), 1);
    assert_eq!(
        loaded.findings_so_far[0].llm_model,
        Some("claude-3.5-sonnet".to_string())
    );

    let _ = fs::remove_file(temp_path);
}

/// Test: Checkpoint - empty findings list
#[test]
fn test_checkpoint_empty_findings() {
    let checkpoint = Checkpoint::new("empty-test", "/tmp/empty", Utc::now());
    let temp_path = "/tmp/test_checkpoint_empty.json";

    checkpoint.save(temp_path).unwrap();

    let loaded = Checkpoint::load(temp_path).unwrap();
    assert!(loaded.findings_so_far.is_empty());
    assert_eq!(loaded.file_count, 0);

    let _ = fs::remove_file(temp_path);
}

/// Test: Checkpoint - analyzed files tracking
#[test]
fn test_checkpoint_analyzed_files_tracking() {
    let checkpoint = Checkpoint::new("files-test", "/tmp/files", Utc::now());
    let temp_path = "/tmp/test_checkpoint_files.json";

    let mut cp = checkpoint.clone();
    cp.analyzed_files = vec![
        "src/main.rs".to_string(),
        "src/lib.rs".to_string(),
        "src/utils.rs".to_string(),
    ];
    cp.file_count = 3;
    cp.save(temp_path).unwrap();

    let loaded = Checkpoint::load(temp_path).unwrap();
    assert_eq!(loaded.analyzed_files.len(), 3);
    assert!(loaded.analyzed_files.contains(&"src/main.rs".to_string()));
    assert_eq!(loaded.file_count, 3);

    let _ = fs::remove_file(temp_path);
}

/// Test: Checkpoint - scan ID preservation
#[test]
fn test_checkpoint_scan_id_preservation() {
    let checkpoint = Checkpoint::new("unique-scan-id-12345", "/tmp/scan", Utc::now());
    let temp_path = "/tmp/test_checkpoint_scan_id.json";

    checkpoint.save(temp_path).unwrap();

    let loaded = Checkpoint::load(temp_path).unwrap();
    assert_eq!(loaded.scan_id, "unique-scan-id-12345");

    let _ = fs::remove_file(temp_path);
}

/// Test: Checkpoint - timestamp preservation
#[test]
fn test_checkpoint_timestamp_preservation() {
    let checkpoint = Checkpoint::new("timestamp-test", "/tmp/timestamp", Utc::now());
    let temp_path = "/tmp/test_checkpoint_timestamp.json";

    let original_timestamp = checkpoint.started_at;
    checkpoint.save(temp_path).unwrap();

    let loaded = Checkpoint::load(temp_path).unwrap();
    assert_eq!(loaded.started_at, original_timestamp);

    let _ = fs::remove_file(temp_path);
}

/// Test: Checkpoint - multiple findings accumulation
#[test]
fn test_checkpoint_multiple_findings_accumulation() {
    let checkpoint = Checkpoint::new("multi-finding-test", "/tmp/multi", Utc::now());
    let temp_path = "/tmp/test_checkpoint_multi.json";

    let mut cp = checkpoint.clone();
    cp.findings_so_far.push(create_test_finding());
    cp.findings_so_far.push(create_test_finding());
    cp.findings_so_far.push(create_complete_finding());
    cp.save(temp_path).unwrap();

    let loaded = Checkpoint::load(temp_path).unwrap();
    assert_eq!(loaded.findings_so_far.len(), 3);

    let _ = fs::remove_file(temp_path);
}

/// Test: Checkpoint - phase progression tracking
#[test]
fn test_checkpoint_phase_progression() {
    let checkpoint = Checkpoint::new("phase-test", "/tmp/phase", Utc::now());
    let temp_path = "/tmp/test_checkpoint_phase.json";

    let mut cp = checkpoint.clone();
    cp.current_phase = ScanPhase::Semgrep;
    cp.save(temp_path).unwrap();

    let loaded = Checkpoint::load(temp_path).unwrap();
    assert_eq!(loaded.current_phase, ScanPhase::Semgrep);

    let _ = fs::remove_file(temp_path);
}
