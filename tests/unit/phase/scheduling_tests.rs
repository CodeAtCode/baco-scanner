use baco::checkpoint::ScanPhase;
use baco::scanner::PhaseGraph;
use baco::scanner::Scanner;

#[test]
fn test_parallel_phase_count() {
    // Parallel phases: Indexing, Semgrep, LlmStaticAnalysis = 3
    let parallel_count = Scanner::scheduled_parallel_phases();
    assert_eq!(parallel_count, 3, "Expected 3 parallel phases");
}

#[test]
fn test_sequential_phase_count() {
    // Sequential phases: 12 (CweRouting through Reporting)
    let sequential_count = Scanner::scheduled_sequential_phases();
    assert_eq!(sequential_count, 12, "Expected 12 sequential phases");
}

#[test]
fn test_total_phase_count() {
    // Total: 3 parallel + 12 sequential = 15
    let (parallel, sequential) = Scanner::scheduled_phase_counts();
    let total = parallel + sequential;
    assert_eq!(total, 15, "Expected 15 total phases");
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
fn test_llm_static_analysis_is_parallel_phase() {
    // LlmStaticAnalysis should be in parallel phases (phase 3)
    let phase_graph = PhaseGraph::new();
    let phases = phase_graph.phases();

    let llm_static_idx = phases
        .iter()
        .position(|p| *p == ScanPhase::LlmStaticAnalysis);
    assert!(
        llm_static_idx.is_some(),
        "LlmStaticAnalysis should be in PhaseGraph"
    );
    assert_eq!(
        llm_static_idx.unwrap(),
        2,
        "LlmStaticAnalysis should be at index 2 (3rd phase)"
    );
}

#[test]
fn test_validate_is_sequential_phase() {
    // Validate should be in sequential phases (phase 7)
    // Order: Indexing(0), Semgrep(1), LlmStaticAnalysis(2), CweRouting(3),
    //        LlmDiscovery(4), LlmVerification(5), Validate(6)
    let phase_graph = PhaseGraph::new();
    let phases = phase_graph.phases();

    let validate_idx = phases.iter().position(|p| *p == ScanPhase::Validate);
    assert!(validate_idx.is_some(), "Validate should be in PhaseGraph");
    assert_eq!(
        validate_idx.unwrap(),
        6,
        "Validate should be at index 6 (7th phase)"
    );
}
