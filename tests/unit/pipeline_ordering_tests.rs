use baco::checkpoint::ScanPhase;
use baco::scanner::PhaseGraph;

/// The actual phases executed by the hard-coded orchestrator (parallel + sequential).
/// Parallel: Indexing, Semgrep, LlmStaticAnalysis
/// Sequential: CweRouting, LlmDiscovery, LlmVerification, SecurityAgentVerification,
///             TicketCrossRef, GitAnalysis, CrossFileAnalysis, ConfidenceScoring,
///             AiAggregation, ThreatModeling, RootCauseDedup, MultiVerifier,
///             AutoPatching, CveBootstrap, PocCompiler, VariantSearch, Reporting
fn actual_pipeline_phases() -> Vec<ScanPhase> {
    vec![
        // Parallel
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        // Sequential
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
fn test_pipeline_has_expected_phase_count() {
    let phases = actual_pipeline_phases();
    // 3 parallel + 17 sequential = 20 total
    assert_eq!(phases.len(), 20, "Pipeline should have 20 phases");
}

#[test]
fn test_pipeline_starts_with_indexing() {
    let phases = actual_pipeline_phases();
    assert_eq!(phases[0], ScanPhase::Indexing);
}

#[test]
fn test_pipeline_ends_with_reporting() {
    let phases = actual_pipeline_phases();
    assert_eq!(*phases.last().unwrap(), ScanPhase::Reporting);
}

#[test]
fn test_pipeline_cwe_routing_after_llm_static() {
    let phases = actual_pipeline_phases();
    let llm_static_idx = phases
        .iter()
        .position(|p| *p == ScanPhase::LlmStaticAnalysis)
        .unwrap();
    let cwe_routing_idx = phases
        .iter()
        .position(|p| *p == ScanPhase::CweRouting)
        .unwrap();
    assert!(
        cwe_routing_idx > llm_static_idx,
        "CweRouting must come after LlmStaticAnalysis"
    );
}

#[test]
fn test_pipeline_threat_modeling_before_root_cause_dedup() {
    let phases = actual_pipeline_phases();
    let tm_idx = phases
        .iter()
        .position(|p| *p == ScanPhase::ThreatModeling)
        .unwrap();
    let rcd_idx = phases
        .iter()
        .position(|p| *p == ScanPhase::RootCauseDedup)
        .unwrap();
    assert!(
        tm_idx < rcd_idx,
        "ThreatModeling must come before RootCauseDedup"
    );
}

#[test]
fn test_pipeline_no_duplicate_phases() {
    let phases = actual_pipeline_phases();
    let mut seen = std::collections::HashSet::new();
    for phase in &phases {
        assert!(
            seen.insert(phase),
            "Duplicate phase in pipeline: {:?}",
            phase
        );
    }
}

#[test]
fn test_pipeline_root_cause_dedup_before_reporting() {
    let phases = actual_pipeline_phases();
    let rcd_idx = phases
        .iter()
        .position(|p| *p == ScanPhase::RootCauseDedup)
        .unwrap();
    let report_idx = phases
        .iter()
        .position(|p| *p == ScanPhase::Reporting)
        .unwrap();
    assert!(
        rcd_idx < report_idx,
        "RootCauseDedup must come before Reporting"
    );
}

#[test]
fn test_phase_graph_metadata_phase_count() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();
    // PhaseGraph has 20 phases (matches the runtime pipeline)
    assert_eq!(phases.len(), 20, "PhaseGraph should have 20 phases");
}

#[test]
fn test_phase_graph_ends_with_reporting() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();
    assert_eq!(*phases.last().unwrap(), ScanPhase::Reporting);
}

#[test]
fn test_phase_graph_metadata_covers_all_phases() {
    let graph = PhaseGraph::new();
    for phase in graph.phases() {
        let meta = graph.get_metadata(phase);
        assert!(meta.is_some(), "Phase {:?} has no metadata", phase);
        let meta = meta.unwrap();
        assert!(meta.phase_number > 0);
        assert_eq!(meta.total_phases, graph.phases().len() as u8);
    }
}

#[test]
fn test_phase_graph_next_phase() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    for i in 0..phases.len() - 1 {
        let current = &phases[i];
        let expected_next = &phases[i + 1];
        let actual_next = graph.next_phase(current).unwrap();
        assert_eq!(
            actual_next, expected_next,
            "next_phase({:?}) mismatch",
            current
        );
    }

    // Last phase has no next
    let last = phases.last().unwrap();
    assert!(graph.next_phase(last).is_none());
}

#[test]
fn test_resume_from_covers_all_sequential_phases() {
    // Every sequential phase must have a resume_from entry that routes to
    // the next phase in the pipeline
    let tmp = tempfile::tempdir().unwrap();
    let sequential_phases = vec![
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
    ];

    let expected_next = vec![
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
        ScanPhase::Complete,
    ];

    for (current, expected) in sequential_phases.iter().zip(expected_next.iter()) {
        let path = tmp.path().join(format!("{:?}.json", current));
        let now = chrono::Utc::now();
        let mut cp = baco::checkpoint::Checkpoint::new("test", "/tmp/p", now);
        cp.current_phase = current.clone();
        cp.save(path.to_str().unwrap()).unwrap();

        let next = baco::checkpoint::Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
        assert_eq!(
            &next, expected,
            "resume_from({:?}) should return {:?}",
            current, expected
        );
    }
}
