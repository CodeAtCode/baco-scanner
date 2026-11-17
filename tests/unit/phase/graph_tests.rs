//! Tests for the PhaseGraph data structure
//!
//! Covers:
//! - PhaseGraph construction
//! - Phase ordering and adjacency
//! - Metadata retrieval

use baco::checkpoint::ScanPhase;
use baco::scanner::PhaseGraph;

#[test]
fn test_phase_graph_construction() {
    let graph = PhaseGraph::new();
    assert!(!graph.phases().is_empty());
}

#[test]
fn test_phase_graph_has_15_phases() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.phases().len(), 15);
}

#[test]
fn test_phase_graph_start_phase() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();
    assert_eq!(phases[0], ScanPhase::Indexing);
}

#[test]
fn test_phase_graph_end_phase() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();
    assert_eq!(phases[14], ScanPhase::Reporting);
}

#[test]
fn test_phase_graph_no_duplicates() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();
    let mut seen = std::collections::HashSet::new();
    for phase in phases {
        assert!(seen.insert(phase), "Duplicate phase: {:?}", phase);
    }
}

#[test]
fn test_phase_graph_metadata_for_all_phases() {
    let graph = PhaseGraph::new();
    for phase in graph.phases() {
        let meta = graph.get_metadata(phase);
        assert!(meta.is_some(), "Missing metadata for {:?}", phase);
        let meta = meta.unwrap();
        assert!(!meta.display_name.is_empty());
        assert!(!meta.description.is_empty());
    }
}

#[test]
fn test_phase_graph_next_phase() {
    let graph = PhaseGraph::new();
    let phases = graph.phases();

    // Test that next_phase returns the correct phase for all but the last
    for i in 0..phases.len() - 1 {
        let current = &phases[i];
        let expected_next = &phases[i + 1];
        let actual_next = graph.next_phase(current);
        assert_eq!(
            actual_next,
            Some(expected_next),
            "next_phase({:?}) mismatch",
            current
        );
    }

    // Last phase has no next
    let last = phases.last().unwrap();
    assert!(graph.next_phase(last).is_none());
}
