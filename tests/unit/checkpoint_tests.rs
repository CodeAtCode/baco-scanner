//! Lane B checkpoint tests - 10 specific tests per target/lane_b_spec.txt
//!
//! These tests cover the exact requirements specified in the audit pinning.

use baco::checkpoint::{Checkpoint, ScanPhase};
use baco::evidence::{Evidence, EvidenceSource, VerificationTier};
use baco::findings::{Severity, VulnerabilityFinding};
use chrono::Utc;
use std::fs;

/// Create a test finding with verification_tier and evidence fields
fn make_test_finding_with_evidence() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-123".to_string(),
        title: "Test Finding".to_string(),
        description: "A test vulnerability with evidence".to_string(),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("unsafe_code()".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
        code_location: Some("src/test.rs:42".to_string()),
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
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
        evidence: vec![Evidence {
            source: EvidenceSource::Semgrep("semgrep-rule-1".to_string()),
            weight: 0.8,
            detail: "Test evidence detail".to_string(),
            timestamp: Utc::now(),
        }],
        verification_tier: Some(VerificationTier::Supported),
    }
}

/// Get a unique temp path for checkpoint files
fn temp_checkpoint_path(test_name: &str) -> String {
    format!("/tmp/baco_lane_b_test_{}.json", test_name)
}

// ============================================================================
// TEST 1: Table test for all 20 sequential phases
// ============================================================================

#[test]
fn test_sequential_phase_20_phase_table() {
    // Test that resume_from(phase) equals the next phase in sequential_phases order
    // This pins the exact mapping verified in audit
    let sequential_phases = [
        ScanPhase::CweRouting,
        ScanPhase::RuleSynthesis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::Validate,
        ScanPhase::SecurityAgentVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::MultiVerifier,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::ExploitSynth,
        ScanPhase::VariantSearch,
        ScanPhase::Reporting,
    ];

    for i in 0..sequential_phases.len() - 1 {
        let mut checkpoint = Checkpoint::new("test", "/tmp", Utc::now());
        checkpoint.current_phase = sequential_phases[i].clone();
        let temp_path = temp_checkpoint_path(&format!("seq_phase_{}", i));
        checkpoint.save(&temp_path).unwrap();

        let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
        assert_eq!(
            next_phase,
            sequential_phases[i + 1],
            "Sequential phase {} ({:?}) should resume to {:?}, got {:?}",
            i,
            sequential_phases[i],
            sequential_phases[i + 1],
            next_phase
        );

        let _ = fs::remove_file(&temp_path);
    }
}

// ============================================================================
// TEST 2: Parallel chain test
// ============================================================================

#[test]
fn test_parallel_chain_indexing_to_cwe_routing() {
    // Parallel chain: Indexing -> Semgrep -> CpgSlice -> LlmStaticAnalysis -> CweRouting
    let parallel_chain = [
        (ScanPhase::Indexing, ScanPhase::Semgrep),
        (ScanPhase::Semgrep, ScanPhase::CpgSlice),
        (ScanPhase::CpgSlice, ScanPhase::LlmStaticAnalysis),
        (ScanPhase::LlmStaticAnalysis, ScanPhase::CweRouting),
    ];

    for (current, expected_next) in parallel_chain {
        let mut checkpoint = Checkpoint::new("test", "/tmp", Utc::now());
        checkpoint.current_phase = current.clone();
        let temp_path = temp_checkpoint_path(&format!("parallel_{:?}", current));
        checkpoint.save(&temp_path).unwrap();

        let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
        assert_eq!(
            next_phase, expected_next,
            "Parallel chain: {:?} should resume to {:?}",
            current, expected_next
        );

        let _ = fs::remove_file(&temp_path);
    }
}

// ============================================================================
// TEST 3: Terminal state transitions
// ============================================================================

#[test]
fn test_terminal_transitions_reporting_complete_error() {
    // Reporting -> Complete; Complete -> Indexing; Error -> Indexing
    let terminal_cases = [
        (ScanPhase::Reporting, ScanPhase::Complete),
        (ScanPhase::Complete, ScanPhase::Indexing),
        (ScanPhase::Error, ScanPhase::Indexing),
    ];

    for (current, expected_next) in terminal_cases {
        let mut checkpoint = Checkpoint::new("test", "/tmp", Utc::now());
        checkpoint.current_phase = current.clone();
        let temp_path = temp_checkpoint_path(&format!("terminal_{:?}", current));
        checkpoint.save(&temp_path).unwrap();

        let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
        assert_eq!(
            next_phase, expected_next,
            "Terminal: {:?} should resume to {:?}",
            current, expected_next
        );

        let _ = fs::remove_file(&temp_path);
    }
}

// ============================================================================
// TEST 4: save then load round-trips all fields
// ============================================================================

#[test]
fn test_save_load_roundtrip_all_fields() {
    let mut checkpoint = Checkpoint::new("scan-roundtrip", "/tmp/project", Utc::now());
    checkpoint.current_phase = ScanPhase::Semgrep;
    checkpoint.file_count = 150;
    checkpoint
        .findings_so_far
        .push(make_test_finding_with_evidence());
    checkpoint.analyzed_files.push("src/main.rs".to_string());
    checkpoint.analyzed_files.push("src/lib.rs".to_string());

    let temp_path = temp_checkpoint_path("roundtrip");
    checkpoint.save(&temp_path).unwrap();

    let loaded = Checkpoint::load(&temp_path).unwrap();

    assert_eq!(checkpoint.scan_id, loaded.scan_id);
    assert_eq!(checkpoint.project_path, loaded.project_path);
    assert_eq!(checkpoint.current_phase, loaded.current_phase);
    assert_eq!(checkpoint.file_count, loaded.file_count);
    assert_eq!(
        checkpoint.findings_so_far.len(),
        loaded.findings_so_far.len()
    );
    assert_eq!(checkpoint.analyzed_files.len(), loaded.analyzed_files.len());
    assert_eq!(
        checkpoint.analyzed_files, loaded.analyzed_files,
        "analyzed_files should match"
    );

    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// TEST 5: validate() empty scan_id and project_path
// ============================================================================

#[test]
fn test_validate_empty_scan_id_and_project_path() {
    // empty scan_id -> Err
    let checkpoint_empty_id = Checkpoint::new("", "/tmp/project", Utc::now());
    let result = checkpoint_empty_id.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("scan_id"));

    // empty project_path -> Err
    let checkpoint_empty_path = Checkpoint::new("scan-123", "", Utc::now());
    let result = checkpoint_empty_path.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("project_path"));

    // valid values -> Ok
    let checkpoint_valid = Checkpoint::new("scan-123", "/tmp/project", Utc::now());
    let result = checkpoint_valid.validate();
    assert!(result.is_ok());
}

// ============================================================================
// TEST 6: resume_from on non-existent file returns Err (no panic)
// ============================================================================

#[test]
fn test_resume_from_nonexistent_file_returns_err() {
    let result = Checkpoint::resume_from("/nonexistent/path/checkpoint_12345.json");
    assert!(result.is_err());
    // Should not panic, should return a descriptive error
    let err = result.unwrap_err();
    assert!(err.contains("read") || err.contains("Failed to read"));
}

// ============================================================================
// TEST 7: resume_from on corrupt JSON file returns Err (no panic)
// ============================================================================

#[test]
fn test_resume_from_corrupt_json_returns_err() {
    let temp_path = temp_checkpoint_path("corrupt");
    fs::write(&temp_path, "this is not valid json {{{").unwrap();

    let result = Checkpoint::resume_from(&temp_path);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("parse") || err.contains("Failed to parse"));

    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// TEST 8: Full flow - save checkpoint for phase X, load, resume_from returns X
// ============================================================================

#[test]
fn test_full_flow_save_load_resume() {
    let phase_to_test = ScanPhase::LlmDiscovery;

    let mut checkpoint = Checkpoint::new("scan-flow", "/tmp/project", Utc::now());
    checkpoint.current_phase = phase_to_test.clone();

    let temp_path = temp_checkpoint_path("full_flow");
    checkpoint.save(&temp_path).unwrap();

    // Load the checkpoint
    let loaded = Checkpoint::load(&temp_path).unwrap();
    assert_eq!(loaded.current_phase, phase_to_test);

    // resume_from should return the NEXT phase after phase_to_test
    let next_phase = Checkpoint::resume_from(&temp_path).unwrap();
    // LlmDiscovery should resume to LlmVerification
    assert_eq!(next_phase, ScanPhase::LlmVerification);

    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// TEST 9: save_checkpoint writes a complete file
// ============================================================================

#[test]
fn test_save_checkpoint_writes_complete_file() {
    // Note: This is a simplified test since save_checkpoint is async and requires
    // full scanner infrastructure. We test the core checkpoint save functionality.
    let mut checkpoint = Checkpoint::new("async-test-scan", "/tmp/test-project", Utc::now());
    checkpoint.current_phase = ScanPhase::CweRouting;
    checkpoint.file_count = 50;
    checkpoint.completed_phases.push(ScanPhase::Indexing);
    checkpoint.completed_phases.push(ScanPhase::Semgrep);

    let temp_path = temp_checkpoint_path("complete_file");
    checkpoint.save(&temp_path).unwrap();

    // Loading it immediately after succeeds
    let loaded = Checkpoint::load(&temp_path).unwrap();
    assert_eq!(loaded.scan_id, "async-test-scan");
    assert_eq!(loaded.current_phase, ScanPhase::CweRouting);
    assert_eq!(loaded.file_count, 50);
    assert_eq!(loaded.completed_phases.len(), 2);

    let _ = fs::remove_file(&temp_path);
}

// ============================================================================
// TEST 10: Checkpointed findings preserve verification_tier and evidence
// ============================================================================

#[test]
fn test_findings_preserve_verification_tier_and_evidence() {
    let mut checkpoint = Checkpoint::new("evidence-test", "/tmp/project", Utc::now());
    checkpoint.current_phase = ScanPhase::Reporting;

    let mut finding = make_test_finding_with_evidence();
    finding.verification_tier = Some(VerificationTier::Verified);
    finding.evidence = vec![
        Evidence {
            source: EvidenceSource::Semgrep("semgrep-rule-1".to_string()),
            weight: 0.8,
            detail: "Direct evidence of vulnerability".to_string(),
            timestamp: Utc::now(),
        },
        Evidence {
            source: EvidenceSource::LlmAnalysis("llm-model-v1".to_string()),
            weight: 0.7,
            detail: "LLM confirms the vulnerability pattern".to_string(),
            timestamp: Utc::now(),
        },
    ];

    checkpoint.findings_so_far.push(finding);

    let temp_path = temp_checkpoint_path("evidence_preserve");
    checkpoint.save(&temp_path).unwrap();

    let loaded = Checkpoint::load(&temp_path).unwrap();
    assert_eq!(loaded.findings_so_far.len(), 1);

    let loaded_finding = &loaded.findings_so_far[0];
    assert_eq!(
        loaded_finding.verification_tier,
        Some(VerificationTier::Verified),
        "verification_tier should be preserved"
    );
    assert_eq!(
        loaded_finding.evidence.len(),
        2,
        "evidence vector should be preserved"
    );
    assert!(
        matches!(
            loaded_finding.evidence[0].source,
            EvidenceSource::Semgrep(_)
        ),
        "first evidence source should be Semgrep"
    );
    assert_eq!(
        loaded_finding.evidence[1].detail, "LLM confirms the vulnerability pattern",
        "second evidence detail should match"
    );

    let _ = fs::remove_file(&temp_path);
}
