//! PhaseGraph tests — verify the 24-phase pipeline ordering and navigation.
//!
//! The PhaseGraph must mirror the real orchestrator pipeline exactly:
//! Indexing → Semgrep → CpgSlice → LlmStaticAnalysis → CweRouting → RuleSynthesis → … → Reporting.

use baco::checkpoint::ScanPhase;
use baco::scanner::PhaseGraph;

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
fn test_display_name_format_indexing() {
    let graph = PhaseGraph::new();
    let display = graph.display_name(&ScanPhase::Indexing);
    assert_eq!(display, "1/24 Indexing");
}

#[test]
fn test_display_name_format_cpg_slice() {
    let graph = PhaseGraph::new();
    let display = graph.display_name(&ScanPhase::CpgSlice);
    assert_eq!(display, "3/24 CPG Slice");
}

#[test]
fn test_display_name_format_llm_static() {
    let graph = PhaseGraph::new();
    let display = graph.display_name(&ScanPhase::LlmStaticAnalysis);
    assert_eq!(display, "4/24 LLM Static Analysis");
}

#[test]
fn test_display_name_format_reporting() {
    let graph = PhaseGraph::new();
    let display = graph.display_name(&ScanPhase::Reporting);
    assert_eq!(display, "24/24 Reporting");
}

#[test]
fn test_display_name_total_count_matches_graph() {
    let graph = PhaseGraph::new();
    for phase in graph.phases() {
        let display = graph.display_name(phase);
        let expected_total = graph.total_phases() as u8;
        // Extract total from display string "NN/24 Name"
        if let Some(slash_pos) = display.find('/') {
            if let Some(space_pos) = display[slash_pos..].find(' ') {
                let total_str = &display[slash_pos + 1..slash_pos + space_pos];
                if let Ok(total) = total_str.parse::<u8>() {
                    assert_eq!(total, expected_total, "Total mismatch for {:?}", phase);
                }
            }
        }
    }
}

#[test]
fn test_phase_index_derived_from_graph() {
    let graph = PhaseGraph::new();
    // Verify that phase_index matches the index in display_name
    for (i, phase) in graph.phases().iter().enumerate() {
        let expected_index = i + 1;
        let actual_index = graph.phase_index(phase);
        assert_eq!(
            actual_index, expected_index,
            "Index mismatch for {:?}",
            phase
        );
    }
}
