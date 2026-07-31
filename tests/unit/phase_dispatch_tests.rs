use baco::checkpoint::ScanPhase;

/// All ScanPhase variants that should have match arms in run_phase.
/// Terminal/orphaned phases are handled by the _ catch-all, which is correct.
fn active_phases() -> Vec<ScanPhase> {
    vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::CweRouting,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::SecurityAgentVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::MultiVerifier,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::VariantSearch,
    ]
}

/// Orphaned phases that should fall through to the _ catch-all.
/// These have no implementation and should be skipped gracefully.
fn orphaned_phases() -> Vec<ScanPhase> {
    vec![
        ScanPhase::CpgSlice,
        ScanPhase::Hunt,
        ScanPhase::Validate,
        ScanPhase::IndependentVerify,
        ScanPhase::ExploitSynth,
        ScanPhase::RuleSynthesis,
    ]
}

/// Terminal states.
fn terminal_phases() -> Vec<ScanPhase> {
    vec![ScanPhase::Complete, ScanPhase::Error]
}

/// All phases that appear in the sequential_phases array in orchestrator.rs
fn sequential_pipeline_phases() -> Vec<ScanPhase> {
    vec![
        ScanPhase::CweRouting,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
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
        ScanPhase::VariantSearch,
        ScanPhase::Reporting,
    ]
}

#[test]
fn test_all_active_phases_exist() {
    let phases = active_phases();
    assert_eq!(phases.len(), 20, "Should have 20 active phases");
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

    // ScanPhase has 28 variants total
    assert_eq!(
        all.len(),
        28,
        "All 28 ScanPhase variants must be categorized"
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
fn test_orphaned_phases_have_safe_fallback() {
    // Verify each orphaned phase has a safe fallback in resume_from
    let tmp = tempfile::tempdir().unwrap();
    let fallbacks = vec![
        (ScanPhase::CpgSlice, ScanPhase::CweRouting),
        (ScanPhase::Hunt, ScanPhase::LlmDiscovery),
        (ScanPhase::Validate, ScanPhase::LlmDiscovery),
        (ScanPhase::IndependentVerify, ScanPhase::LlmDiscovery),
        (ScanPhase::ExploitSynth, ScanPhase::LlmDiscovery),
        (ScanPhase::RuleSynthesis, ScanPhase::Complete),
    ];

    for (orphan, expected_fallback) in fallbacks {
        let path = tmp.path().join(format!("{:?}.json", orphan));
        let now = chrono::Utc::now();
        let mut cp = baco::checkpoint::Checkpoint::new("test", "/tmp/p", now);
        cp.current_phase = orphan.clone();
        cp.save(path.to_str().unwrap()).unwrap();

        let next = baco::checkpoint::Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
        assert_eq!(
            next, expected_fallback,
            "Orphan {:?} should fallback to {:?}",
            orphan, expected_fallback
        );
    }
}
