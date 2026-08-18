use baco::checkpoint::ScanPhase;
use baco::scanner::PhaseGraph;
use baco::scanner::Scanner;

#[test]
fn test_parallel_phase_count() {
    // Parallel phases: Indexing, Semgrep, CpgSlice, LlmStaticAnalysis = 4
    let parallel_count = Scanner::scheduled_parallel_phases();
    assert_eq!(parallel_count, 4, "Expected 4 parallel phases");
}

#[test]
fn test_sequential_phase_count() {
    // Sequential phases: 20 (including Validate)
    let sequential_count = Scanner::scheduled_sequential_phases();
    assert_eq!(sequential_count, 20, "Expected 20 sequential phases");
}

#[test]
fn test_total_phase_count() {
    // Total: 4 parallel + 20 sequential = 24
    let (parallel, sequential) = Scanner::scheduled_phase_counts();
    let total = parallel + sequential;
    assert_eq!(total, 24, "Expected 24 total phases");
}

#[test]
fn test_phase_graph_matches_schedule() {
    // Verify that scheduled phases match PhaseGraph declaration
    let phase_graph = PhaseGraph::new();
    let graph_phases = phase_graph.phases();

    let (parallel_count, sequential_count) = Scanner::scheduled_phase_counts();
    let scheduled_total = parallel_count + sequential_count;

    assert_eq!(
        graph_phases.len(),
        scheduled_total,
        "PhaseGraph declares {} phases but scheduler has {} ({} parallel + {} sequential)",
        graph_phases.len(),
        scheduled_total,
        parallel_count,
        sequential_count
    );
}

#[test]
fn test_cpg_slice_is_parallel_phase() {
    // CpgSlice should be in parallel phases (phase 3)
    let phase_graph = PhaseGraph::new();
    let phases = phase_graph.phases();

    let cpg_slice_idx = phases.iter().position(|p| *p == ScanPhase::CpgSlice);
    assert!(cpg_slice_idx.is_some(), "CpgSlice should be in PhaseGraph");
    assert_eq!(
        cpg_slice_idx.unwrap(),
        2,
        "CpgSlice should be at index 2 (3rd phase)"
    );
}

#[test]
fn test_validate_is_sequential_phase() {
    // Validate should be in sequential phases (phase 9)
    let phase_graph = PhaseGraph::new();
    let phases = phase_graph.phases();

    let validate_idx = phases.iter().position(|p| *p == ScanPhase::Validate);
    assert!(validate_idx.is_some(), "Validate should be in PhaseGraph");
    assert_eq!(
        validate_idx.unwrap(),
        8,
        "Validate should be at index 8 (9th phase)"
    );
}
