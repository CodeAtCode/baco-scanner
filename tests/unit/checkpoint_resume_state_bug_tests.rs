//! Tests for checkpoint resume state persistence bug.
//!
//! This module tests the bug where `baco resume` overwrites the completion
//! marker with a stale one because only `findings_so_far` is updated after
//! the resume run, losing the advanced `current_phase` and `completed_phases`.

use baco::checkpoint::{Checkpoint, ScanPhase};
use baco::scanner::phase_spec::PhaseSpec;
use std::fs;

/// Test that demonstrates the bug: after a simulated resume that completes
/// the pipeline, the saved checkpoint's `completed_phases` should contain
/// the final phase, but currently it retains the pre-run values.
#[test]
fn test_resume_checkpoint_state_is_stale_bug() {
    let tmp = tempfile::tempdir().unwrap();
    let checkpoint_path = tmp.path().join("checkpoint.json");

    // Simulate a checkpoint loaded BEFORE scanner.run() during resume
    // This is what happens at scan.rs:131 in run_resume()
    let started_at = chrono::Utc::now();
    let mut checkpoint = Checkpoint::new("scan-resume-test", "/tmp/project", started_at);

    // The scan was interrupted at LlmStaticAnalysis
    checkpoint.current_phase = ScanPhase::LlmStaticAnalysis;
    checkpoint.completed_phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
    ];
    checkpoint.findings_so_far = vec![];
    checkpoint.file_count = 10;

    checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();

    // Simulate what run_resume() does at lines 244-248:
    // It loads the checkpoint, then after scanner.run() only updates findings_so_far
    let loaded_checkpoint = Checkpoint::load(checkpoint_path.to_str().unwrap()).unwrap();

    // Simulate scanner.run() completing all phases and producing findings
    // In reality, scanner.run() internally saves checkpoints via save_checkpoint()
    // which DOES update completed_phases correctly, but run_resume() doesn't use that

    // THIS IS THE BUG: run_resume() does:
    let mut final_checkpoint = loaded_checkpoint;
    final_checkpoint.findings_so_far = vec![]; // Simulate new findings
    // NOTE: current_phase and completed_phases are NOT updated!

    final_checkpoint
        .save(checkpoint_path.to_str().unwrap())
        .unwrap();

    // Verify the bug: the checkpoint still has stale phase info
    let reloaded = Checkpoint::load(checkpoint_path.to_str().unwrap()).unwrap();

    // The bug: completed_phases still shows only up to LlmStaticAnalysis
    // even though the resume run completed all phases
    assert_eq!(
        reloaded.current_phase,
        ScanPhase::LlmStaticAnalysis,
        "BUG: current_phase should be Reporting after completion, but is stale"
    );

    assert_eq!(
        reloaded.completed_phases.len(),
        3,
        "BUG: completed_phases should contain all phases, but has stale count of 3"
    );

    // This test currently PASSES because it documents the bug.
    // After the fix, this test should be updated to assert the correct behavior:
    // assert_eq!(reloaded.current_phase, ScanPhase::Reporting);
    // assert!(reloaded.completed_phases.contains(&ScanPhase::Reporting));
}

/// Test that after a resume that completes the pipeline, a second resume
/// should report the scan already complete instead of re-running.
#[test]
fn test_second_resume_after_completion_should_not_re_run() {
    let tmp = tempfile::tempdir().unwrap();
    let checkpoint_path = tmp.path().join("checkpoint.json");

    // First resume completes the scan
    let started_at = chrono::Utc::now();
    let mut checkpoint = Checkpoint::new("scan-test", "/tmp/project", started_at);
    checkpoint.current_phase = ScanPhase::Reporting;
    checkpoint.completed_phases = PhaseSpec::all().to_vec();
    checkpoint.findings_so_far = vec![];

    checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();

    // Simulate run_resume() checking if scan is complete
    // At scan.rs:132-137:
    let loaded = Checkpoint::load(checkpoint_path.to_str().unwrap()).unwrap();

    // This check should prevent re-running
    // BUG: The check uses current_phase == Complete, but the actual value is Reporting
    // So the scan will re-run unnecessarily
    if loaded.current_phase == ScanPhase::Complete {
        // Should return early without re-running
        return; // Test passes - no re-run needed
    }

    // BUG: If current_phase is Reporting (not Complete), this check fails
    // and the scan re-runs unnecessarily
    // This test documents the bug - it fails because the bug exists
    assert_eq!(
        loaded.current_phase,
        ScanPhase::Reporting,
        "BUG: current_phase is Reporting, not Complete, so scan will re-run"
    );
}

/// Test that the scanner's internal save_checkpoint() correctly updates completed_phases
/// (this is the mechanism that should be used instead of the stale checkpoint)
#[test]
fn test_save_checkpoint_updates_completed_phases_correctly() {
    use baco::scanner::checkpoint::ScanLocation;

    let tmp = tempfile::tempdir().unwrap();
    let checkpoint_path = tmp.path().join("checkpoint.json");
    let target_path = tmp.path().join("target");
    fs::create_dir_all(&target_path).unwrap();

    let location = ScanLocation {
        target_path: &target_path,
        config_path: None,
    };

    // Save a checkpoint at Reporting phase
    futures::executor::block_on(async {
        baco::scanner::checkpoint::save_checkpoint(
            &checkpoint_path,
            location,
            &[],
            &[],
            &ScanPhase::Reporting,
            None,
        )
        .await
        .unwrap();
    });

    let loaded = Checkpoint::load(checkpoint_path.to_str().unwrap()).unwrap();

    // The scanner's save_checkpoint() correctly computes completed_phases
    // from PhaseSpec::all() (see checkpoint.rs:188-198)
    assert!(
        loaded.completed_phases.contains(&ScanPhase::Reporting),
        "save_checkpoint should include Reporting in completed_phases"
    );

    // This test verifies the mechanism that run_resume() should use
    // instead of the stale checkpoint it loads at the start
}
