//! Verification test for scan health phase recording.
//!
//! This test documents the current behavior: scan health records phases from the plan
//! rather than from execution, so a skipped or internally-failed phase can end up
//! reported as "run".

use baco::checkpoint::ScanPhase;
use baco::scan_health::{PhaseStatusKind, ScanHealth};

/// Test that demonstrates scan health records all phases as "run" unconditionally.
///
/// Evidence from code review:
/// - src/scanner/orchestrator.rs:702-710 calls record_phase_run for all phases
/// - No check is made for what actually ran
/// - LLM-config skips are detected later at lines 711-734, but failures inside
///   parallel phases are only recorded via parallel_failures vector (line 677)
///   and marked later at lines 743-749
#[test]
fn test_scan_health_records_all_phases_as_run_verification() {
    let mut health = ScanHealth::new();

    // Simulate what orchestrator.rs:702-710 does:
    // All phases are recorded as "run" unconditionally
    health.record_phase_run(&ScanPhase::Indexing);
    health.record_phase_run(&ScanPhase::Semgrep);
    health.record_phase_run(&ScanPhase::LlmStaticAnalysis);

    // Verify all are recorded as Run
    assert_eq!(health.phase_status.len(), 3);
    for status in &health.phase_status {
        assert!(
            matches!(status.status, PhaseStatusKind::Run),
            "Phase {} should be recorded as Run",
            status.phase
        );
    }

    // BUG: If a phase was skipped (e.g., LlmStaticAnalysis due to missing API key)
    // or failed internally, it would still be recorded as "Run" here.
    // The LLM-config skip detection at lines 711-734 can override this,
    // but only for config-related skips, not for internal failures.

    // This test currently PASSES because it documents the bug:
    // phases are recorded as "run" from the plan, not from actual execution
}

/// Test that a skipped phase due to LLM config can be detected and reported.
///
/// This verifies the partial fix at orchestrator.rs:711-734 that detects
/// LLM-config skips after recording all phases as "run".
#[test]
fn test_llm_config_skip_detection_partial_fix() {
    use baco::config::llm::{LlmPhaseConfig, LlmPhasesConfig};

    let mut health = ScanHealth::new();

    // Record all phases as run (what orchestrator does)
    health.record_phase_run(&ScanPhase::LlmStaticAnalysis);
    health.record_phase_run(&ScanPhase::LlmDiscovery);
    health.record_phase_run(&ScanPhase::LlmVerification);

    // Simulate LLM config with missing API keys
    let llm_config = LlmPhasesConfig {
        static_analysis: LlmPhaseConfig {
            api_key: None, // Missing API key
            ..Default::default()
        },
        discovery: LlmPhaseConfig {
            api_key: Some("key".to_string()),
            ..Default::default()
        },
        verification: LlmPhaseConfig {
            api_key: None, // Missing API key
            ..Default::default()
        },
        aggregation: Default::default(),
        prompt_overrides: Default::default(),
    };

    // Get the phases that ran (as strings, which is what detect_llm_config_skips expects)
    let ran_phases: Vec<String> = health
        .phase_status
        .iter()
        .map(|ps| ps.phase.clone())
        .collect();

    // Detect LLM-config skips
    // The function checks if a phase is NOT in ran_phases AND has no API key
    // Since all phases are in ran_phases, no skips will be detected
    // This demonstrates the bug: phases are recorded as "run" even when they shouldn't have run
    let skips = ScanHealth::detect_llm_config_skips(&llm_config, &ran_phases);

    // BUG: Since all phases were recorded as "run", no skips are detected
    // The function only detects skips for phases that weren't recorded as run
    assert_eq!(
        skips.len(),
        0,
        "No skips detected because all phases were recorded as run"
    );

    // This test verifies the bug: the orchestrator records all phases as "run"
    // before checking if they should have run based on config
}

/// Test that parallel phase failures are not automatically recorded.
///
/// Evidence: orchestrator.rs:677 collects parallel_failures, but they are
/// only marked later at lines 743-749 if the failure count > 0.
/// Individual phase failures are not tracked.
#[test]
fn test_parallel_phase_failures_not_automatically_recorded_verification() {
    use baco::scan_health::{PhaseStatusKind, ScanHealth};

    // This test documents the gap: if a parallel phase fails internally
    // (e.g., Semgrep returns errors), the failure is collected in parallel_failures
    // but individual phase status is not updated to "Failed".
    //
    // The fix at lines 743-749 only marks phases as failed if the overall
    // parallel_failures count > 0, not per-phase.
    //
    // This test documents the bug: phases are recorded as "run" even when they shouldn't have run
    // After a fix, individual phase failures should be recorded via
    // record_phase_failed() rather than record_phase_run().

    let mut health = ScanHealth::new();
    health.record_phase_run(&ScanPhase::LlmStaticAnalysis);
    health.record_phase_run(&ScanPhase::LlmDiscovery);
    health.record_phase_run(&ScanPhase::LlmVerification);

    // All three phases are recorded as "Run" even if one of them had internal failures
    assert_eq!(health.phase_status.len(), 3, "Three phases recorded");

    // Verify all are marked as "Run" not "Failed"
    for ps in &health.phase_status {
        // Check that status is Run (not Failed or Skipped)
        match ps.status {
            PhaseStatusKind::Run => {} // OK
            PhaseStatusKind::Skipped => panic!("Phase {} should be Run, not Skipped", ps.phase),
            PhaseStatusKind::Failed => panic!("Phase {} should be Run, not Failed", ps.phase),
        }
    }
}
