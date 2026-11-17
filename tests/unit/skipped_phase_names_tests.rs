//! `skipped_sequential_phase_names` must stay derived from the pipeline.

use baco::scanner::phase_spec::PhaseSpec;

#[test]
fn test_skipped_sequential_phase_names_matches_the_sequential_pipeline() {
    let names = baco::scanner::orchestrator::skipped_sequential_phase_names();
    let expected: Vec<String> = PhaseSpec::sequential()
        .iter()
        .map(|p| p.to_string())
        .collect();

    assert_eq!(
        names, expected,
        "the user-facing skipped list must be the sequential pipeline, not a copied list"
    );
    assert_eq!(
        names.len(),
        12,
        "the core pipeline has twelve sequential phases"
    );
}

#[test]
fn test_skipped_sequential_phase_names_excludes_removed_phases() {
    let names = baco::scanner::orchestrator::skipped_sequential_phase_names();

    for removed in [
        "CpgSlice",
        "RuleSynthesis",
        "SecurityAgentVerification",
        "ThreatModeling",
        "AutoPatching",
        "PocCompiler",
        "ExploitSynth",
        "VariantSearch",
    ] {
        assert!(
            !names.iter().any(|n| n == removed),
            "removed phase '{removed}' must not appear in the skipped list"
        );
    }

    assert!(
        names.iter().any(|n| n == "CweRouting"),
        "CweRouting runs sequentially and must be listed"
    );
}
