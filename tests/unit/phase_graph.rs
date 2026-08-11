//! PhaseGraph tests — verify the 24-phase pipeline ordering and navigation.
//!
//! The PhaseGraph must mirror the real orchestrator pipeline exactly:
//! Indexing → Semgrep → CpgSlice → LlmStaticAnalysis → CweRouting → RuleSynthesis → … → Reporting.

use baco::checkpoint::ScanPhase;
use baco::config::ScannerConfig;
use baco::scanner::{Orchestrator, PhaseGraph};

const EXPECTED_PHASES: [ScanPhase; 24] = [
    ScanPhase::Indexing,
    ScanPhase::Semgrep,
    ScanPhase::CpgSlice,
    ScanPhase::LlmStaticAnalysis,
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

#[test]
fn test_phase_count_is_24() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.phases().len(), 24);
}

#[test]
fn test_first_phase_is_indexing() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.phases()[0], ScanPhase::Indexing);
}

#[test]
fn test_last_phase_is_reporting() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();
    assert_eq!(phases[phases.len() - 1], ScanPhase::Reporting);
}

#[test]
fn test_cpg_slice_at_index_2() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.phases()[2], ScanPhase::CpgSlice);
}

#[test]
fn test_llm_static_at_index_3() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.phases()[3], ScanPhase::LlmStaticAnalysis);
}

#[test]
fn test_rule_synthesis_at_index_5() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.phases()[5], ScanPhase::RuleSynthesis);
}

#[test]
fn test_exploit_synth_at_index_21() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.phases()[21], ScanPhase::ExploitSynth);
}

#[test]
fn test_full_phase_ordering() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    for (i, expected) in EXPECTED_PHASES.iter().enumerate() {
        assert_eq!(
            phases[i], *expected,
            "Phase mismatch at index {i}: expected {expected:?}, got {:?}",
            phases[i]
        );
    }
}

#[test]
fn test_no_duplicate_phases() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();
    let unique_count: std::collections::HashSet<_> = phases.iter().collect();
    assert_eq!(
        unique_count.len(),
        phases.len(),
        "Duplicate phases detected"
    );
}

#[test]
fn test_next_phase_semgrep_to_cpg_slice() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.next_phase(&ScanPhase::Semgrep),
        Some(&ScanPhase::CpgSlice)
    );
}

#[test]
fn test_next_phase_cpg_slice_to_llm_static() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.next_phase(&ScanPhase::CpgSlice),
        Some(&ScanPhase::LlmStaticAnalysis)
    );
}

#[test]
fn test_next_phase_llm_static_to_cwe_routing() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.next_phase(&ScanPhase::LlmStaticAnalysis),
        Some(&ScanPhase::CweRouting)
    );
}

#[test]
fn test_next_phase_cwe_routing_to_rule_synthesis() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.next_phase(&ScanPhase::CweRouting),
        Some(&ScanPhase::RuleSynthesis)
    );
}

#[test]
fn test_next_phase_poc_compiler_to_exploit_synth() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.next_phase(&ScanPhase::PocCompiler),
        Some(&ScanPhase::ExploitSynth)
    );
}

#[test]
fn test_next_phase_exploit_synth_to_variant_search() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.next_phase(&ScanPhase::ExploitSynth),
        Some(&ScanPhase::VariantSearch)
    );
}

#[test]
fn test_next_phase_variant_search_to_reporting() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.next_phase(&ScanPhase::VariantSearch),
        Some(&ScanPhase::Reporting)
    );
}

#[test]
fn test_next_phase_reporting_is_none() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.next_phase(&ScanPhase::Reporting), None);
}

#[test]
fn test_next_phase_complete_is_none() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.next_phase(&ScanPhase::Complete), None);
}

#[test]
fn test_previous_phase_indexing_is_none() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.previous_phase(&ScanPhase::Indexing), None);
}

#[test]
fn test_previous_phase_reporting_to_variant_search() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.previous_phase(&ScanPhase::Reporting),
        Some(&ScanPhase::VariantSearch)
    );
}

#[test]
fn test_previous_phase_cwe_routing_to_llm_static() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.previous_phase(&ScanPhase::CweRouting),
        Some(&ScanPhase::LlmStaticAnalysis)
    );
}

#[test]
fn test_previous_phase_rule_synthesis_to_cwe_routing() {
    let graph = PhaseGraph::new();
    assert_eq!(
        graph.previous_phase(&ScanPhase::RuleSynthesis),
        Some(&ScanPhase::CweRouting)
    );
}

#[test]
fn test_metadata_total_phases_is_24() {
    let graph = PhaseGraph::new();
    for phase in graph.phases() {
        let meta = graph.get_metadata(phase).unwrap();
        assert_eq!(meta.total_phases, 24, "total_phases mismatch for {phase:?}");
    }
}

#[test]
fn test_metadata_phase_numbers_sequential() {
    let graph = PhaseGraph::new();
    for (i, phase) in graph.phases().iter().enumerate() {
        let meta = graph.get_metadata(phase).unwrap();
        assert_eq!(
            meta.phase_number,
            (i + 1) as u8,
            "Phase number mismatch for {phase:?}: expected {}, got {}",
            i + 1,
            meta.phase_number
        );
    }
}

#[test]
fn test_metadata_display_names() {
    let graph = PhaseGraph::new();

    let indexing_meta = graph.get_metadata(&ScanPhase::Indexing).unwrap();
    assert_eq!(indexing_meta.display_name, "Indexing");

    let cwe_meta = graph.get_metadata(&ScanPhase::CweRouting).unwrap();
    assert_eq!(cwe_meta.display_name, "CWE Routing");

    let cpg_meta = graph.get_metadata(&ScanPhase::CpgSlice).unwrap();
    assert_eq!(cpg_meta.display_name, "CPG Slice");

    let rule_meta = graph.get_metadata(&ScanPhase::RuleSynthesis).unwrap();
    assert_eq!(rule_meta.display_name, "Rule Synthesis");

    let exploit_meta = graph.get_metadata(&ScanPhase::ExploitSynth).unwrap();
    assert_eq!(exploit_meta.display_name, "Exploit Synthesis");

    let reporting_meta = graph.get_metadata(&ScanPhase::Reporting).unwrap();
    assert_eq!(reporting_meta.display_name, "Reporting");
    assert_eq!(reporting_meta.phase_number, 24);

    let validate_meta = graph.get_metadata(&ScanPhase::Validate).unwrap();
    assert_eq!(validate_meta.display_name, "Validate");
    assert_eq!(validate_meta.phase_number, 9);
}

#[test]
fn test_default_equals_new() {
    let default_graph = PhaseGraph::default();
    let new_graph = PhaseGraph::new();

    assert_eq!(default_graph.phases().len(), new_graph.phases().len());

    for (default_phase, new_phase) in default_graph.phases().iter().zip(new_graph.phases().iter()) {
        assert_eq!(default_phase, new_phase);
    }
}

#[test]
fn test_orchestrator_phase_graph_has_24_phases() {
    let config = ScannerConfig::default();
    let orchestrator = Orchestrator::new(&config);
    let phase_graph = orchestrator.phase_graph();

    assert_eq!(phase_graph.phases().len(), 24);
    assert_eq!(phase_graph.phases()[0], ScanPhase::Indexing);
    assert_eq!(phase_graph.phases()[23], ScanPhase::Reporting);
}

#[test]
fn test_orchestrator_metadata_accessible() {
    let config = ScannerConfig::default();
    let orchestrator = Orchestrator::new(&config);
    let phase_graph = orchestrator.phase_graph();

    let indexing_meta = phase_graph.get_metadata(&ScanPhase::Indexing);
    assert!(indexing_meta.is_some());
    assert_eq!(indexing_meta.unwrap().display_name, "Indexing");
}
