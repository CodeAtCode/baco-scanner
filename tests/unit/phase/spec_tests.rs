//! Tests for phase_spec.rs - the single-source pipeline definition.
//!
//! These tests lock the PhaseSpec table to current behavior with inline
//! expected values (no dependencies on deleted originals).

use baco::checkpoint::ScanPhase;
use baco::config::scanner::ScanPipelineProfile;
use baco::scanner::phase_spec::PhaseSpec;

#[test]
fn slots_len_is_23() {
    assert_eq!(PhaseSpec::slots().len(), 23);
}

#[test]
fn table_order_matches_23_phase_sequence() {
    // Inline 23-phase sequence (byte-identical to historical definition)
    let expected: [ScanPhase; 23] = [
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
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::ExploitSynth,
        ScanPhase::VariantSearch,
        ScanPhase::Reporting,
    ];
    assert_eq!(PhaseSpec::all(), &expected);
}

#[test]
fn table_sequential_matches_19_phase_sequence() {
    // Inline 19-sequential-phase sequence
    let expected: [ScanPhase; 19] = [
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
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::ExploitSynth,
        ScanPhase::VariantSearch,
        ScanPhase::Reporting,
    ];
    assert_eq!(PhaseSpec::sequential(), &expected);
}

#[test]
fn table_core_matches_14_phase_sequence() {
    // Inline 14-core-phase sequence
    let expected: [ScanPhase; 14] = [
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::CweRouting,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::RootCauseDedup,
        ScanPhase::CveBootstrap,
        ScanPhase::Reporting,
    ];
    assert_eq!(PhaseSpec::core_phases(), &expected);
}

#[test]
fn table_experimental_matches_9_phase_sequence() {
    // Inline 9-experimental-phase sequence
    let expected: [ScanPhase; 9] = [
        ScanPhase::CpgSlice,
        ScanPhase::RuleSynthesis,
        ScanPhase::Validate,
        ScanPhase::SecurityAgentVerification,
        ScanPhase::ThreatModeling,
        ScanPhase::AutoPatching,
        ScanPhase::PocCompiler,
        ScanPhase::ExploitSynth,
        ScanPhase::VariantSearch,
    ];
    assert_eq!(PhaseSpec::experimental_phases(), &expected);
}

#[test]
fn resume_from_transitions_match_26_case_table() {
    // Inline resume_from transition table for all 25 cases (23 phases + Complete + Error)
    let test_cases: [(ScanPhase, ScanPhase); 25] = [
        (ScanPhase::Indexing, ScanPhase::Semgrep),
        (ScanPhase::Semgrep, ScanPhase::CpgSlice),
        (ScanPhase::CpgSlice, ScanPhase::LlmStaticAnalysis),
        (ScanPhase::LlmStaticAnalysis, ScanPhase::CweRouting),
        (ScanPhase::CweRouting, ScanPhase::RuleSynthesis),
        (ScanPhase::RuleSynthesis, ScanPhase::LlmDiscovery),
        (ScanPhase::LlmDiscovery, ScanPhase::LlmVerification),
        (ScanPhase::LlmVerification, ScanPhase::Validate),
        (ScanPhase::Validate, ScanPhase::SecurityAgentVerification),
        (
            ScanPhase::SecurityAgentVerification,
            ScanPhase::TicketCrossRef,
        ),
        (ScanPhase::TicketCrossRef, ScanPhase::GitAnalysis),
        (ScanPhase::GitAnalysis, ScanPhase::CrossFileAnalysis),
        (ScanPhase::CrossFileAnalysis, ScanPhase::ConfidenceScoring),
        (ScanPhase::ConfidenceScoring, ScanPhase::AiAggregation),
        (ScanPhase::AiAggregation, ScanPhase::ThreatModeling),
        (ScanPhase::ThreatModeling, ScanPhase::RootCauseDedup),
        (ScanPhase::RootCauseDedup, ScanPhase::AutoPatching),
        (ScanPhase::AutoPatching, ScanPhase::CveBootstrap),
        (ScanPhase::CveBootstrap, ScanPhase::PocCompiler),
        (ScanPhase::PocCompiler, ScanPhase::ExploitSynth),
        (ScanPhase::ExploitSynth, ScanPhase::VariantSearch),
        (ScanPhase::VariantSearch, ScanPhase::Reporting),
        (ScanPhase::Reporting, ScanPhase::Complete),
        (ScanPhase::Complete, ScanPhase::Indexing),
        (ScanPhase::Error, ScanPhase::Indexing),
    ];

    for (phase, expected_next) in test_cases {
        let actual = PhaseSpec::resume_from(&phase);
        assert_eq!(
            actual, expected_next,
            "resume_from({:?}) = {:?}, expected {:?}",
            phase, actual, expected_next
        );
    }
}

#[test]
fn progress_messages_identical() {
    // Test all phases have non-empty messages
    for phase in PhaseSpec::all() {
        let msg = PhaseSpec::progress_message(phase);
        assert!(!msg.is_empty(), "progress_message({:?}) is empty", phase);
    }

    // Verify specific messages match expected format
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::CweRouting),
        "CWE routing (routing findings to specialized models)..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::RuleSynthesis),
        "Rule synthesis (generating semgrep rules from LLM analysis)..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::LlmDiscovery),
        "LLM discovery (enriching findings with context)..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::LlmVerification),
        "LLM verification (validating findings)..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::Validate),
        "Validate (LLM-as-judge rationale validation)..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::SecurityAgentVerification),
        "SecurityAgent verification (tool-based validation)..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::TicketCrossRef),
        "Searching ticket systems for references..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::GitAnalysis),
        "Analyzing Git history for related commits..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::CrossFileAnalysis),
        "Cross-file dependency analysis..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::ConfidenceScoring),
        "Calculating confidence scores..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::AiAggregation),
        "AI aggregation (generating executive summary)..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::ThreatModeling),
        "Threat modeling (STRIDE analysis)..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::RootCauseDedup),
        "Root cause deduplication..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::AutoPatching),
        "Auto-patching with staging validation..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::CveBootstrap),
        "CVE bootstrap..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::PocCompiler),
        "PoC compilation check..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::ExploitSynth),
        "Exploit synthesis with sandbox..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::VariantSearch),
        "Variant search..."
    );
    assert_eq!(
        PhaseSpec::progress_message(&ScanPhase::Reporting),
        "Generating reports (JSON/HTML/SARIF)..."
    );
}

#[test]
fn effective_core_profile_yields_14() {
    let effective = PhaseSpec::effective(&ScanPipelineProfile::Core);
    assert_eq!(effective.len(), 14);

    // Verify it matches the expected core phases
    assert_eq!(effective.as_slice(), PhaseSpec::core_phases());
}

#[test]
fn effective_all_profile_yields_23() {
    let effective = PhaseSpec::effective(&ScanPipelineProfile::All);
    assert_eq!(effective.len(), 23);
    assert_eq!(effective.as_slice(), PhaseSpec::all());
}

#[test]
fn parallel_phases_are_first_4() {
    use baco::scanner::phase_spec::PhaseKind;
    let slots = PhaseSpec::slots();

    // First 4 must be parallel
    for (i, slot) in slots.iter().take(4).enumerate() {
        assert_eq!(slot.kind, PhaseKind::Parallel);
        assert_eq!(slot.phase, PhaseSpec::parallel()[i]);
    }
}

#[test]
fn sequential_phases_start_at_index_4() {
    use baco::scanner::phase_spec::PhaseKind;
    let slots = PhaseSpec::slots();

    // Slots 4-23 must be sequential
    for (i, slot) in slots.iter().skip(4).enumerate() {
        assert_eq!(slot.kind, PhaseKind::Sequential);
        assert_eq!(slot.phase, PhaseSpec::sequential()[i]);
    }
}

#[test]
fn from_phase_lookup_is_total() {
    // Every phase in all() must have a slot
    for phase in PhaseSpec::all() {
        let slot = PhaseSpec::from_phase(phase);
        assert!(slot.is_some(), "from_phase({:?}) returned None", phase);
        assert_eq!(&slot.unwrap().phase, phase);
    }
}

#[test]
fn core_and_experimental_are_disjoint() {
    let core = PhaseSpec::core_phases();
    let experimental = PhaseSpec::experimental_phases();

    for c in core {
        assert!(
            !experimental.contains(c),
            "Phase {:?} is in both core and experimental",
            c
        );
    }
}

#[test]
fn core_plus_experimental_equals_all() {
    let mut combined = Vec::new();
    combined.extend_from_slice(PhaseSpec::core_phases());
    combined.extend_from_slice(PhaseSpec::experimental_phases());

    // Check that combined has 23 phases and all are unique
    assert_eq!(combined.len(), 23);

    // Verify every phase in all() appears exactly once in combined
    for phase in PhaseSpec::all() {
        let count = combined.iter().filter(|&p| p == phase).count();
        assert_eq!(
            count, 1,
            "Phase {:?} appears {} times in combined (expected 1)",
            phase, count
        );
    }
}
