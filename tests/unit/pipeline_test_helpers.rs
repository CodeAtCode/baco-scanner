//! Shared test helpers for pipeline/phase-related tests
//!
//! Used by: phase_dispatch_tests.rs, pipeline_ordering_tests.rs

use baco::checkpoint::ScanPhase;

/// All ScanPhase variants that should have match arms in run_phase.
/// Terminal/orphaned phases are handled by the _ catch-all, which is correct.
/// Order matches the orchestrator for test validation.
pub fn active_phases() -> Vec<ScanPhase> {
    vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::CweRouting,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
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
        ScanPhase::VariantSearch,
        ScanPhase::Reporting,
    ]
}

/// Orphaned phases that should fall through to the _ catch-all.
/// These have no implementation and should be skipped gracefully.
pub fn orphaned_phases() -> Vec<ScanPhase> {
    vec![
        ScanPhase::CpgSlice,
        ScanPhase::Hunt,
        ScanPhase::Validate,
        ScanPhase::IndependentVerify,
        ScanPhase::ExploitSynth,
        ScanPhase::RuleSynthesis,
    ]
}

/// Terminal states.
pub fn terminal_phases() -> Vec<ScanPhase> {
    vec![ScanPhase::Complete, ScanPhase::Error]
}

/// All phases that appear in the sequential_phases array in orchestrator.rs
pub fn sequential_pipeline_phases() -> Vec<ScanPhase> {
    vec![
        ScanPhase::CweRouting,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
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
        ScanPhase::VariantSearch,
        ScanPhase::Reporting,
    ]
}

/// The actual phases executed by the hard-coded orchestrator (parallel + sequential).
/// Built from active_phases minus orphaned/terminal phases.
pub fn actual_pipeline_phases() -> Vec<ScanPhase> {
    active_phases()
}
