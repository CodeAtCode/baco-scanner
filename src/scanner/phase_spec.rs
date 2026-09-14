//! Single source of truth for the BACO 24-phase pipeline definition.
//!
//! This module defines the canonical pipeline structure: 4 parallel phases
//! followed by 20 sequential phases. All phase-related queries (order,
//! grouping, profile filtering, resume transitions, progress messages)
//! derive from this table — no redundant definitions elsewhere.

use crate::checkpoint::ScanPhase;
use crate::config::scanner::ScanPipelineProfile;

/// Phase execution mode: parallel (concurrent) or sequential (ordered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseKind {
    Parallel,
    Sequential,
}

/// A single slot in the pipeline table, carrying all metadata needed for
/// phase queries without touching other modules.
#[derive(Debug, Clone)]
pub struct PhaseSlot {
    /// The phase this slot represents.
    pub phase: ScanPhase,
    /// Parallel or sequential execution mode.
    pub kind: PhaseKind,
    /// True if this phase is part of the core profile.
    pub core: bool,
    /// Optional config gate key for feature-flag gating (unused this stage).
    pub config_gate_key: Option<&'static str>,
    /// Executor key for dispatch (unused this stage).
    pub executor_key: &'static str,
}

/// The canonical 24-phase pipeline table.
///
/// Order: 4 parallel phases (Indexing, Semgrep, CpgSlice, LlmStaticAnalysis)
/// followed by 20 sequential phases (CweRouting through Reporting).
pub struct PhaseSpec;

impl PhaseSpec {
    /// Returns the full 24-phase slot table.
    ///
    /// Order is byte-identical to the historical definition:
    /// - Parallel: Indexing, Semgrep, CpgSlice, LlmStaticAnalysis
    /// - Sequential: CweRouting, RuleSynthesis, LlmDiscovery, LlmVerification,
    ///   Validate, SecurityAgentVerification, TicketCrossRef, GitAnalysis,
    ///   CrossFileAnalysis, ConfidenceScoring, AiAggregation, ThreatModeling,
    ///   RootCauseDedup, MultiVerifier, AutoPatching, CveBootstrap, PocCompiler,
    ///   ExploitSynth, VariantSearch, Reporting
    pub const fn slots() -> &'static [PhaseSlot; 24] {
        &SLOTS
    }

    /// Return all phases in execution order (24 total).
    pub fn all() -> &'static [ScanPhase; 24] {
        &ALL_PHASES
    }

    /// Return only the sequential phases (20 total).
    pub fn sequential() -> &'static [ScanPhase; 20] {
        &SEQUENTIAL_PHASES
    }

    /// Return only the parallel phases (4 total).
    pub fn parallel() -> &'static [ScanPhase; 4] {
        &PARALLEL_PHASES
    }

    /// Total phase count (24).
    pub const fn total() -> usize {
        24
    }

    /// Look up the slot for a given phase.
    pub fn from_phase(phase: &ScanPhase) -> Option<&'static PhaseSlot> {
        SLOTS.iter().find(|s| &s.phase == phase)
    }

    /// Return core phases only (14 total).
    pub fn core_phases() -> &'static [ScanPhase; 14] {
        &CORE_PHASES
    }

    /// Return experimental phases only (10 total).
    pub fn experimental_phases() -> &'static [ScanPhase; 10] {
        &EXPERIMENTAL_PHASES
    }

    /// Compute the effective phase set for a given profile.
    ///
    /// - Core: 14 phases (excludes experimental)
    /// - All: 24 phases (all enabled)
    pub fn effective(profile: &ScanPipelineProfile) -> Vec<ScanPhase> {
        match profile {
            ScanPipelineProfile::Core => CORE_PHASES.to_vec(),
            ScanPipelineProfile::All => ALL_PHASES.to_vec(),
        }
    }

    /// Compute the next phase to resume from, given a completed phase.
    ///
    /// Byte-identical semantics to checkpoint::Checkpoint::resume_from.
    pub fn resume_from(phase: &ScanPhase) -> ScanPhase {
        match phase {
            // Parallel phases (run concurrently: Indexing, Semgrep, CpgSlice, LlmStaticAnalysis)
            ScanPhase::Indexing => ScanPhase::Semgrep,
            ScanPhase::Semgrep => ScanPhase::CpgSlice,
            ScanPhase::CpgSlice => ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmStaticAnalysis => ScanPhase::CweRouting,
            // Sequential phases
            ScanPhase::CweRouting => ScanPhase::RuleSynthesis,
            ScanPhase::RuleSynthesis => ScanPhase::LlmDiscovery,
            ScanPhase::LlmDiscovery => ScanPhase::LlmVerification,
            ScanPhase::LlmVerification => ScanPhase::Validate,
            ScanPhase::Validate => ScanPhase::SecurityAgentVerification,
            ScanPhase::SecurityAgentVerification => ScanPhase::TicketCrossRef,
            ScanPhase::TicketCrossRef => ScanPhase::GitAnalysis,
            ScanPhase::GitAnalysis => ScanPhase::CrossFileAnalysis,
            ScanPhase::CrossFileAnalysis => ScanPhase::ConfidenceScoring,
            ScanPhase::ConfidenceScoring => ScanPhase::AiAggregation,
            ScanPhase::AiAggregation => ScanPhase::ThreatModeling,
            ScanPhase::ThreatModeling => ScanPhase::RootCauseDedup,
            ScanPhase::RootCauseDedup => ScanPhase::MultiVerifier,
            ScanPhase::MultiVerifier => ScanPhase::AutoPatching,
            ScanPhase::AutoPatching => ScanPhase::CveBootstrap,
            ScanPhase::CveBootstrap => ScanPhase::PocCompiler,
            ScanPhase::PocCompiler => ScanPhase::ExploitSynth,
            ScanPhase::ExploitSynth => ScanPhase::VariantSearch,
            ScanPhase::VariantSearch => ScanPhase::Reporting,
            ScanPhase::Reporting => ScanPhase::Complete,
            ScanPhase::Complete | ScanPhase::Error => ScanPhase::Indexing,
        }
    }

    /// Return the progress message for a given phase.
    ///
    /// Byte-identical to the historical get_phase_message implementation.
    pub fn progress_message(phase: &ScanPhase) -> &'static str {
        match phase {
            ScanPhase::CweRouting => "CWE routing (routing findings to specialized models)...",
            ScanPhase::RuleSynthesis => {
                "Rule synthesis (generating semgrep rules from LLM analysis)..."
            }
            ScanPhase::LlmDiscovery => "LLM discovery (enriching findings with context)...",
            ScanPhase::LlmVerification => "LLM verification (validating findings)...",
            ScanPhase::Validate => "Validate (LLM-as-judge rationale validation)...",
            ScanPhase::SecurityAgentVerification => {
                "SecurityAgent verification (tool-based validation)..."
            }
            ScanPhase::TicketCrossRef => "Searching ticket systems for references...",
            ScanPhase::GitAnalysis => "Analyzing Git history for related commits...",
            ScanPhase::CrossFileAnalysis => "Cross-file dependency analysis...",
            ScanPhase::ConfidenceScoring => "Calculating confidence scores...",
            ScanPhase::AiAggregation => "AI aggregation (generating executive summary)...",
            ScanPhase::ThreatModeling => "Threat modeling (STRIDE analysis)...",
            ScanPhase::RootCauseDedup => "Root cause deduplication...",
            ScanPhase::MultiVerifier => "Multi-verifier voting...",
            ScanPhase::AutoPatching => "Auto-patching with staging validation...",
            ScanPhase::CveBootstrap => "CVE bootstrap...",
            ScanPhase::PocCompiler => "PoC compilation check...",
            ScanPhase::ExploitSynth => "Exploit synthesis with sandbox...",
            ScanPhase::VariantSearch => "Variant search...",
            ScanPhase::Reporting => "Generating reports (JSON/HTML/SARIF)...",
            ScanPhase::Indexing => "Indexing project files...",
            ScanPhase::Semgrep => "Running Semgrep...",
            ScanPhase::CpgSlice => "CPG-guided slicing...",
            ScanPhase::LlmStaticAnalysis => "LLM static analysis...",
            ScanPhase::Complete => "Scan complete!",
            ScanPhase::Error => "Error occurred...",
        }
    }
}

// ============================================================================
// Static data: the canonical 24-phase table
// ============================================================================

const SLOTS: [PhaseSlot; 24] = [
    // Parallel phases (4)
    PhaseSlot {
        phase: ScanPhase::Indexing,
        kind: PhaseKind::Parallel,
        core: true,
        config_gate_key: None,
        executor_key: "indexing",
    },
    PhaseSlot {
        phase: ScanPhase::Semgrep,
        kind: PhaseKind::Parallel,
        core: true,
        config_gate_key: None,
        executor_key: "semgrep",
    },
    PhaseSlot {
        phase: ScanPhase::CpgSlice,
        kind: PhaseKind::Parallel,
        core: false, // experimental
        config_gate_key: None,
        executor_key: "cpg_slice",
    },
    PhaseSlot {
        phase: ScanPhase::LlmStaticAnalysis,
        kind: PhaseKind::Parallel,
        core: true,
        config_gate_key: None,
        executor_key: "llm_static",
    },
    // Sequential phases (20)
    PhaseSlot {
        phase: ScanPhase::CweRouting,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "cwe_routing",
    },
    PhaseSlot {
        phase: ScanPhase::RuleSynthesis,
        kind: PhaseKind::Sequential,
        core: false, // experimental
        config_gate_key: None,
        executor_key: "rule_synthesis",
    },
    PhaseSlot {
        phase: ScanPhase::LlmDiscovery,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "llm_discovery",
    },
    PhaseSlot {
        phase: ScanPhase::LlmVerification,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "llm_verification",
    },
    PhaseSlot {
        phase: ScanPhase::Validate,
        kind: PhaseKind::Sequential,
        core: false, // experimental
        config_gate_key: None,
        executor_key: "validate",
    },
    PhaseSlot {
        phase: ScanPhase::SecurityAgentVerification,
        kind: PhaseKind::Sequential,
        core: false, // experimental
        config_gate_key: None,
        executor_key: "security_agent_verification",
    },
    PhaseSlot {
        phase: ScanPhase::TicketCrossRef,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "ticket_cross_ref",
    },
    PhaseSlot {
        phase: ScanPhase::GitAnalysis,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "git_analysis",
    },
    PhaseSlot {
        phase: ScanPhase::CrossFileAnalysis,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "cross_file_analysis",
    },
    PhaseSlot {
        phase: ScanPhase::ConfidenceScoring,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "confidence_scoring",
    },
    PhaseSlot {
        phase: ScanPhase::AiAggregation,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "ai_aggregation",
    },
    PhaseSlot {
        phase: ScanPhase::ThreatModeling,
        kind: PhaseKind::Sequential,
        core: false, // experimental (v3 feature)
        config_gate_key: None,
        executor_key: "threat_modeling",
    },
    PhaseSlot {
        phase: ScanPhase::RootCauseDedup,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "root_cause_dedup",
    },
    PhaseSlot {
        phase: ScanPhase::MultiVerifier,
        kind: PhaseKind::Sequential,
        core: false, // experimental (v3 feature)
        config_gate_key: None,
        executor_key: "multi_verifier",
    },
    PhaseSlot {
        phase: ScanPhase::AutoPatching,
        kind: PhaseKind::Sequential,
        core: false, // experimental (v3 feature)
        config_gate_key: None,
        executor_key: "auto_patching",
    },
    PhaseSlot {
        phase: ScanPhase::CveBootstrap,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "cve_bootstrap",
    },
    PhaseSlot {
        phase: ScanPhase::PocCompiler,
        kind: PhaseKind::Sequential,
        core: false, // experimental (v3 feature)
        config_gate_key: None,
        executor_key: "poc_compiler",
    },
    PhaseSlot {
        phase: ScanPhase::ExploitSynth,
        kind: PhaseKind::Sequential,
        core: false, // experimental (T3.2)
        config_gate_key: None,
        executor_key: "exploit_synth",
    },
    PhaseSlot {
        phase: ScanPhase::VariantSearch,
        kind: PhaseKind::Sequential,
        core: false, // experimental (v3 feature)
        config_gate_key: None,
        executor_key: "variant_search",
    },
    PhaseSlot {
        phase: ScanPhase::Reporting,
        kind: PhaseKind::Sequential,
        core: true,
        config_gate_key: None,
        executor_key: "reporting",
    },
];

// Derived static arrays for efficient queries

const ALL_PHASES: [ScanPhase; 24] = [
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

const PARALLEL_PHASES: [ScanPhase; 4] = [
    ScanPhase::Indexing,
    ScanPhase::Semgrep,
    ScanPhase::CpgSlice,
    ScanPhase::LlmStaticAnalysis,
];

const SEQUENTIAL_PHASES: [ScanPhase; 20] = [
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

const CORE_PHASES: [ScanPhase; 14] = [
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

const EXPERIMENTAL_PHASES: [ScanPhase; 10] = [
    ScanPhase::CpgSlice,
    ScanPhase::RuleSynthesis,
    ScanPhase::Validate,
    ScanPhase::SecurityAgentVerification,
    ScanPhase::ThreatModeling,
    ScanPhase::MultiVerifier,
    ScanPhase::AutoPatching,
    ScanPhase::PocCompiler,
    ScanPhase::ExploitSynth,
    ScanPhase::VariantSearch,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_len_is_24() {
        assert_eq!(PhaseSpec::slots().len(), 24);
    }

    #[test]
    fn table_order_matches_checkpoint_all_phases() {
        let checkpoint_phases = [
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
        assert_eq!(PhaseSpec::all(), &checkpoint_phases);
    }

    #[test]
    fn table_sequential_matches_orchestrator_sequential_phases() {
        let orchestrator_sequential = [
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
        assert_eq!(PhaseSpec::sequential(), &orchestrator_sequential);
    }

    #[test]
    fn table_core_matches_core_phases() {
        let expected_core = [
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
        assert_eq!(PhaseSpec::core_phases(), &expected_core);
    }

    #[test]
    fn table_experimental_matches_experimental_phases() {
        let expected_experimental = [
            ScanPhase::CpgSlice,
            ScanPhase::RuleSynthesis,
            ScanPhase::Validate,
            ScanPhase::SecurityAgentVerification,
            ScanPhase::ThreatModeling,
            ScanPhase::MultiVerifier,
            ScanPhase::AutoPatching,
            ScanPhase::PocCompiler,
            ScanPhase::ExploitSynth,
            ScanPhase::VariantSearch,
        ];
        assert_eq!(PhaseSpec::experimental_phases(), &expected_experimental);
    }

    #[test]
    fn resume_from_transitions_identical_to_checkpoint() {
        // Test all 24 phases
        let test_cases = [
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
            (ScanPhase::RootCauseDedup, ScanPhase::MultiVerifier),
            (ScanPhase::MultiVerifier, ScanPhase::AutoPatching),
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
        // Test all phases have non-empty progress messages
        for phase in PhaseSpec::all() {
            let msg = PhaseSpec::progress_message(phase);
            assert!(!msg.is_empty(), "progress_message({:?}) is empty", phase);
        }

        // Test specific known messages
        assert_eq!(
            PhaseSpec::progress_message(&ScanPhase::CweRouting),
            "CWE routing (routing findings to specialized models)..."
        );
        assert_eq!(
            PhaseSpec::progress_message(&ScanPhase::LlmDiscovery),
            "LLM discovery (enriching findings with context)..."
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
        // Verify no experimental phases in core
        for phase in &effective {
            assert!(
                !PhaseSpec::experimental_phases().contains(phase),
                "Core profile includes experimental phase: {:?}",
                phase
            );
        }
    }

    #[test]
    fn effective_all_profile_yields_24() {
        let effective = PhaseSpec::effective(&ScanPipelineProfile::All);
        assert_eq!(effective.len(), 24);
        assert_eq!(effective.as_slice(), PhaseSpec::all());
    }

    #[test]
    fn parallel_phases_are_first_4() {
        let slots = PhaseSpec::slots();
        for (i, slot) in slots.iter().take(4).enumerate() {
            assert_eq!(slot.kind, PhaseKind::Parallel);
            assert_eq!(slot.phase, PARALLEL_PHASES[i]);
        }
    }

    #[test]
    fn sequential_phases_start_at_index_4() {
        let slots = PhaseSpec::slots();
        for (i, slot) in slots.iter().skip(4).enumerate() {
            assert_eq!(slot.kind, PhaseKind::Sequential);
            assert_eq!(slot.phase, SEQUENTIAL_PHASES[i]);
        }
    }
}
