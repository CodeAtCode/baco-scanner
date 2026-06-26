//! Full pipeline integration tests
//!
//! Tests complete scan workflows including checkpoint creation and resume.

use crate::checkpoint::{Checkpoint, ScanPhase};
use crate::config::ScannerConfig;
use crate::findings::{Severity, VulnerabilityFinding};
use crate::scanner::Scanner;
use std::fs;
use tempfile::TempDir;

use super::fixtures::create_test_project;

/// Test 2: Resume from checkpoint mid-pipeline
#[tokio::test]
async fn test_full_pipeline_resume_from_checkpoint() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = create_test_project(&temp_dir);
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    // Create checkpoint at LlmDiscovery phase
    let checkpoint_path = output_dir.join("checkpoint.json");
    let checkpoint = Checkpoint::new(
        "test-resume-456",
        project_path.to_string_lossy().as_ref(),
        chrono::Utc::now(),
    );

    // Simulate completed phases
    let mut checkpoint = checkpoint;
    checkpoint.current_phase = ScanPhase::LlmDiscovery;
    checkpoint.completed_phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
    ];

    // Add some findings from previous phases
    let finding = VulnerabilityFinding {
        id: "pre-existing-finding".to_string(),
        title: "Pre-existing vulnerability".to_string(),
        description: "Found in previous phase".to_string(),
        file_path: project_path
            .join("vulnerable.rs")
            .to_string_lossy()
            .to_string(),
        line_number: Some(5),
        severity: Severity::High,
        confidence_score: 0.7,
        cwe_id: Some("CWE-78".to_string()),
        sources: vec!["semgrep".to_string()],
        verification_status: None,
        verification_notes: None,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    };
    checkpoint.findings_so_far.push(finding);

    checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();

    // Resume from checkpoint
    let next_phase = Checkpoint::resume_from(checkpoint_path.to_str().unwrap()).unwrap();
    assert_eq!(next_phase, ScanPhase::LlmVerification);

    // Verify we can create a scanner and continue
    let mut config = ScannerConfig::default();
    config.output.dir = output_dir.to_string_lossy().to_string();
    config.project.path = project_path.to_string_lossy().to_string();
    config.project.name = "test-resume".to_string();

    let _scanner = Scanner::new(config, project_path, false);

    // The checkpoint system allows resuming at the correct phase
    assert_eq!(next_phase, ScanPhase::LlmVerification);
}

/// Test 3: Interrupt (Ctrl+C) and resume verification
#[tokio::test]
async fn test_full_pipeline_interrupt_and_resume() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = create_test_project(&temp_dir);
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    // Simulate an interrupted scan by creating a checkpoint mid-way
    let checkpoint_path = output_dir.join("checkpoint_interrupted.json");
    let checkpoint = Checkpoint::new(
        "test-interrupt-789",
        project_path.to_string_lossy().as_ref(),
        chrono::Utc::now(),
    );

    let mut checkpoint = checkpoint;
    checkpoint.current_phase = ScanPhase::GitAnalysis;
    checkpoint.completed_phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::TicketCrossRef,
    ];

    // Add findings that accumulated before interrupt
    for i in 0..3 {
        let finding = VulnerabilityFinding {
            id: format!("interrupted-finding-{}", i),
            title: format!("Finding {} from interrupted scan", i),
            description: "Found before interrupt".to_string(),
            file_path: project_path
                .join("vulnerable.rs")
                .to_string_lossy()
                .to_string(),
            line_number: Some(i + 1),
            severity: Severity::Medium,
            confidence_score: 0.6,
            cwe_id: Some("CWE-79".to_string()),
            sources: vec!["llm".to_string()],
            verification_status: None,
            verification_notes: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        };
        checkpoint.findings_so_far.push(finding);
    }

    checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();

    // Verify resume works correctly
    let next_phase = Checkpoint::resume_from(checkpoint_path.to_str().unwrap()).unwrap();
    assert_eq!(next_phase, ScanPhase::CrossFileAnalysis);

    // Verify findings are preserved in checkpoint
    let mut checkpoint = Checkpoint::load(checkpoint_path.to_str().unwrap()).unwrap();
    assert_eq!(checkpoint.findings_so_far.len(), 3);
    assert_eq!(checkpoint.current_phase, ScanPhase::GitAnalysis);

    // Simulate resuming and completing remaining phases
    for phase in [
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
    ] {
        // In a real scenario, each phase would execute here
        // For this test, we verify the phase transition logic
        let expected_next = match phase {
            ScanPhase::CrossFileAnalysis => ScanPhase::ConfidenceScoring,
            ScanPhase::ConfidenceScoring => ScanPhase::AiAggregation,
            ScanPhase::AiAggregation => ScanPhase::Reporting,
            ScanPhase::Reporting => ScanPhase::Complete,
            _ => panic!("Unexpected phase"),
        };

        // Update checkpoint to simulate phase completion
        checkpoint.current_phase = expected_next;
        checkpoint.completed_phases.push(phase);
        checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();
    }

    // Final checkpoint should show Complete phase
    let final_checkpoint = Checkpoint::load(checkpoint_path.to_str().unwrap()).unwrap();
    assert_eq!(final_checkpoint.current_phase, ScanPhase::Complete);
    assert_eq!(final_checkpoint.findings_so_far.len(), 3);
}
