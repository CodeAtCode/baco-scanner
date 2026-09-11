use baco::checkpoint::ScanPhase;
use baco::config::scanner::ScanPipelineProfile;
use baco::scanner::PhaseGraph;

use crate::pipeline_test_helpers::{
    actual_pipeline_phases, core_profile_phases, effective_phases, experimental_phases,
    sequential_pipeline_phases,
};

#[test]
fn test_pipeline_has_expected_phase_count() {
    let phases = actual_pipeline_phases();
    // 4 parallel + 20 sequential = 24 total
    assert_eq!(phases.len(), 24, "Pipeline should have 24 phases");
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
fn test_pipeline_llm_static_before_cwe_routing() {
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
        llm_static_idx < cwe_routing_idx,
        "LlmStaticAnalysis must come before CweRouting"
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
    // PhaseGraph has 24 phases (matches the runtime pipeline)
    assert_eq!(phases.len(), 24, "PhaseGraph should have 24 phases");
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
    let sequential_phases = sequential_pipeline_phases();

    let expected_next = vec![
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

// Profile-based phase filtering tests

#[test]
fn test_core_profile_excludes_experimental_phases() {
    let core_phases = core_profile_phases();
    let exp_phases = experimental_phases();

    // Core profile should not contain any experimental phases
    for exp_phase in &exp_phases {
        assert!(
            !core_phases.contains(exp_phase),
            "Core profile should not contain experimental phase {:?}",
            exp_phase
        );
    }
}

#[test]
fn test_effective_phases_core_returns_core_set() {
    let effective = effective_phases(ScanPipelineProfile::Core);
    let expected = core_profile_phases();

    assert_eq!(
        effective.len(),
        expected.len(),
        "Core profile effective phases count mismatch"
    );

    for phase in expected {
        assert!(
            effective.contains(&phase),
            "Core profile should include phase {:?}",
            phase
        );
    }
}

#[test]
fn test_effective_phases_all_returns_full_set() {
    let effective = effective_phases(ScanPipelineProfile::All);
    let expected = actual_pipeline_phases();

    assert_eq!(
        effective.len(),
        expected.len(),
        "All profile effective phases count mismatch"
    );
}

#[test]
fn test_experimental_phases_list() {
    let exp_phases = experimental_phases();

    // Verify known experimental phases are present
    assert!(exp_phases.contains(&ScanPhase::CpgSlice));
    assert!(exp_phases.contains(&ScanPhase::RuleSynthesis));
    assert!(exp_phases.contains(&ScanPhase::Validate));
    assert!(exp_phases.contains(&ScanPhase::SecurityAgentVerification));
    assert!(exp_phases.contains(&ScanPhase::ThreatModeling));
    assert!(exp_phases.contains(&ScanPhase::MultiVerifier));
    assert!(exp_phases.contains(&ScanPhase::AutoPatching));
    assert!(exp_phases.contains(&ScanPhase::PocCompiler));
    assert!(exp_phases.contains(&ScanPhase::ExploitSynth));
    assert!(exp_phases.contains(&ScanPhase::VariantSearch));

    // Should have exactly 10 experimental phases
    assert_eq!(exp_phases.len(), 10);
}

#[test]
fn test_core_phases_count() {
    let core_phases = core_profile_phases();
    // 14 core phases (4 parallel - 1 experimental + 10 sequential core + 4 parallel core)
    assert_eq!(core_phases.len(), 14);
}

#[test]
fn test_scan_pipeline_profile_default_is_core() {
    let default: ScanPipelineProfile = Default::default();
    assert_eq!(default, ScanPipelineProfile::Core);
}
