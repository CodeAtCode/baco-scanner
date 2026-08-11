use baco::checkpoint::ScanPhase;

use crate::pipeline_test_helpers::{
    active_phases, orphaned_phases, sequential_pipeline_phases, terminal_phases,
};

#[test]
fn test_all_active_phases_exist() {
    let phases = active_phases();
    assert_eq!(phases.len(), 24, "Should have 24 active phases");
}

#[test]
fn test_no_active_phase_is_orphaned() {
    let active = active_phases();
    let orphaned = orphaned_phases();
    for phase in &active {
        assert!(
            !orphaned.contains(phase),
            "Active phase {:?} is also in orphaned list",
            phase
        );
    }
}

#[test]
fn test_no_active_phase_is_terminal() {
    let active = active_phases();
    let terminal = terminal_phases();
    for phase in &active {
        assert!(
            !terminal.contains(phase),
            "Active phase {:?} is also in terminal list",
            phase
        );
    }
}

#[test]
fn test_sequential_phases_are_subset_of_active() {
    let active = active_phases();
    let sequential = sequential_pipeline_phases();
    for phase in &sequential {
        assert!(
            active.contains(phase),
            "Sequential phase {:?} is not in active phases",
            phase
        );
    }
}

#[test]
fn test_parallel_phases_are_active() {
    let active = active_phases();
    let parallel = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::CpgSlice,
        ScanPhase::LlmStaticAnalysis,
    ];
    for phase in &parallel {
        assert!(
            active.contains(phase),
            "Parallel phase {:?} must be active",
            phase
        );
    }
}

#[test]
fn test_scan_phase_completeness() {
    // Ensure active + orphaned + terminal = all ScanPhase variants
    let mut all = active_phases();
    all.extend(orphaned_phases());
    all.extend(terminal_phases());

    // ScanPhase has 26 variants total
    assert_eq!(
        all.len(),
        26,
        "All 26 ScanPhase variants must be categorized"
    );
}

#[test]
fn test_sequential_phases_first_is_cwe_routing() {
    let phases = sequential_pipeline_phases();
    assert_eq!(phases[0], ScanPhase::CweRouting);
}

#[test]
fn test_sequential_phases_last_is_reporting() {
    let phases = sequential_pipeline_phases();
    assert_eq!(*phases.last().unwrap(), ScanPhase::Reporting);
}

#[test]
fn test_new_phases_have_resume_from_routing() {
    // Verify the three newly-wired phases have proper resume_from transitions
    let tmp = tempfile::tempdir().unwrap();
    let transitions = vec![
        (ScanPhase::Semgrep, ScanPhase::CpgSlice),
        (ScanPhase::CpgSlice, ScanPhase::LlmStaticAnalysis),
        (ScanPhase::CweRouting, ScanPhase::RuleSynthesis),
        (ScanPhase::RuleSynthesis, ScanPhase::LlmDiscovery),
        (ScanPhase::PocCompiler, ScanPhase::ExploitSynth),
        (ScanPhase::ExploitSynth, ScanPhase::VariantSearch),
    ];

    for (from, expected_next) in transitions {
        let path = tmp.path().join(format!("{:?}.json", from));
        let now = chrono::Utc::now();
        let mut cp = baco::checkpoint::Checkpoint::new("test", "/tmp/p", now);
        cp.current_phase = from.clone();
        cp.save(path.to_str().unwrap()).unwrap();

        let next = baco::checkpoint::Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
        assert_eq!(
            next, expected_next,
            "Phase {:?} should transition to {:?}",
            from, expected_next
        );
    }
}
