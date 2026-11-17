//! Tests for phase specification and counts
//!
//! Covers:
//! - Phase counts (all, sequential, parallel)
//! - Phase ordering and metadata
//! - Resume-from transitions

use baco::checkpoint::ScanPhase;
use baco::scanner::PhaseGraph;

use crate::pipeline_test_helpers::{actual_pipeline_phases, sequential_pipeline_phases};

#[test]
fn test_all_phases_count() {
    let all = actual_pipeline_phases();
    assert_eq!(all.len(), 15, "All phases should be 15");
}

#[test]
fn test_sequential_phases_count() {
    let sequential = sequential_pipeline_phases();
    assert_eq!(sequential.len(), 12, "Sequential phases should be 12");
}

#[test]
fn test_parallel_phases_count() {
    let all = actual_pipeline_phases();
    let sequential = sequential_pipeline_phases();
    let parallel_count = all.len() - sequential.len();
    assert_eq!(parallel_count, 3, "Parallel phases should be 3");
}

#[test]
fn test_core_phases_count() {
    // Core profile now equals all 15 phases (no experimental tier)
    let core = actual_pipeline_phases();
    assert_eq!(
        core.len(),
        15,
        "Core profile should have 15 phases (all phases)"
    );
}

#[test]
fn test_phase_graph_has_correct_count() {
    let graph = PhaseGraph::new();
    assert_eq!(graph.phases().len(), 15);
}

#[test]
fn test_phase_metadata_phase_numbers() {
    let graph = PhaseGraph::new();
    for phase in graph.phases() {
        let meta = graph.get_metadata(phase).unwrap();
        assert!(meta.phase_number > 0);
        assert_eq!(meta.total_phases, 15);
    }
}

#[test]
fn test_phase_sequence_starts_with_parallel() {
    let phases = actual_pipeline_phases();
    // First 3 phases are parallel: Indexing, Semgrep, LlmStaticAnalysis
    assert_eq!(phases[0], ScanPhase::Indexing);
    assert_eq!(phases[1], ScanPhase::Semgrep);
    assert_eq!(phases[2], ScanPhase::LlmStaticAnalysis);
}

#[test]
fn test_phase_sequence_continues_sequentially() {
    let phases = actual_pipeline_phases();
    // Phase 3 onwards is sequential starting with CweRouting
    assert_eq!(phases[3], ScanPhase::CweRouting);
}

#[test]
fn test_phase_sequence_ends_with_reporting() {
    let phases = actual_pipeline_phases();
    assert_eq!(phases[14], ScanPhase::Reporting);
}
