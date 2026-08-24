//! Unit tests for scanner pipeline orchestration.
//!
//! Tests cover PhaseGraph from src/scanner/pipeline/.

use baco::checkpoint::ScanPhase;
use baco::scanner::PhaseGraph;

// ============================================================================
// PhaseGraph Construction Tests
// ============================================================================

#[test]
fn test_phase_graph_new_creates_all_phases() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    assert!(!phases.is_empty());
}

#[test]
fn test_phase_graph_first_phase_is_indexing() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    assert_eq!(phases[0], ScanPhase::Indexing);
}

#[test]
fn test_phase_graph_last_phase_is_reporting() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    assert_eq!(phases[phases.len() - 1], ScanPhase::Reporting);
}

#[test]
fn test_phase_graph_has_expected_phase_count() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    assert!(phases.len() >= 19, "Expected at least 19 phases");
}

// ============================================================================
// PhaseMetadata Tests
// ============================================================================

#[test]
fn test_get_metadata_returns_some_for_valid_phase() {
    let graph = PhaseGraph::new();
    let meta = graph.get_metadata(&ScanPhase::Indexing);

    assert!(meta.is_some());
}

#[test]
fn test_phase_metadata_contains_expected_fields() {
    let graph = PhaseGraph::new();
    let meta = graph.get_metadata(&ScanPhase::Semgrep).unwrap();

    assert!(!meta.display_name.is_empty());
    assert!(!meta.description.is_empty());
    assert!(meta.phase_number > 0);
    assert!(meta.total_phases > 0);
}

#[test]
fn test_phase_metadata_phase_number_matches_position() {
    let graph = PhaseGraph::new();

    for (idx, phase) in graph.phases().iter().enumerate() {
        let meta = graph.get_metadata(phase).unwrap();
        assert_eq!(meta.phase_number, (idx + 1) as u8);
    }
}

#[test]
fn test_all_phases_have_metadata() {
    let graph = PhaseGraph::new();

    for phase in graph.phases() {
        let meta = graph.get_metadata(phase);
        assert!(meta.is_some(), "Missing metadata for {:?}", phase);
    }
}

// ============================================================================
// Phase Navigation Tests
// ============================================================================

#[test]
fn test_next_phase_returns_none_for_last_phase() {
    let graph = PhaseGraph::new();
    let result = graph.next_phase(&ScanPhase::Reporting);

    assert!(result.is_none());
}

#[test]
fn test_next_phase_returns_none_for_complete_phase() {
    let graph = PhaseGraph::new();
    let result = graph.next_phase(&ScanPhase::Complete);

    assert!(result.is_none());
}

#[test]
fn test_previous_phase_returns_none_for_first_phase() {
    let graph = PhaseGraph::new();
    let result = graph.previous_phase(&ScanPhase::Indexing);

    assert!(result.is_none());
}

#[test]
fn test_next_phase_chain_from_indexing() {
    let graph = PhaseGraph::new();

    let semgrep = graph.next_phase(&ScanPhase::Indexing);
    assert!(semgrep.is_some());
    assert_eq!(semgrep.unwrap(), &ScanPhase::Semgrep);
}

#[test]
fn test_previous_phase_chain_from_variant_search() {
    let graph = PhaseGraph::new();

    let exploit_synth = graph.previous_phase(&ScanPhase::VariantSearch);
    assert!(exploit_synth.is_some());
    assert_eq!(exploit_synth.unwrap(), &ScanPhase::ExploitSynth);
}

// ============================================================================
// Phase Enablement Tests
// ============================================================================

#[test]
fn test_phase_metadata_display_name_unique() {
    let graph = PhaseGraph::new();
    let mut names: Vec<String> = Vec::new();

    for phase in graph.phases() {
        let meta = graph.get_metadata(phase).unwrap();
        names.push(meta.display_name.clone());
    }

    names.sort();
    names.dedup();

    assert_eq!(
        names.len(),
        graph.phases().len(),
        "Found duplicate display names"
    );
}
