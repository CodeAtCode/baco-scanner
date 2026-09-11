//! Shared test helpers for pipeline/phase-related tests
//!
//! Used by: phase_dispatch_tests.rs, pipeline_ordering_tests.rs

use baco::checkpoint::ScanPhase;
use baco::config::scanner::ScanPipelineProfile;

/// All ScanPhase variants that should have match arms in run_phase.
/// Terminal/orphaned phases are handled by the _ catch-all, which is correct.
/// Order matches the orchestrator for test validation.
pub fn active_phases() -> Vec<ScanPhase> {
    vec![
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
    ]
}

/// Orphaned phases that should fall through to the _ catch-all.
/// These have no implementation and should be skipped gracefully.
pub fn orphaned_phases() -> Vec<ScanPhase> {
    vec![]
}

/// Terminal states.
pub fn terminal_phases() -> Vec<ScanPhase> {
    vec![ScanPhase::Complete, ScanPhase::Error]
}

/// All phases that appear in the sequential_phases array in orchestrator.rs
pub fn sequential_pipeline_phases() -> Vec<ScanPhase> {
    vec![
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
    ]
}

/// The actual phases executed by the hard-coded orchestrator (parallel + sequential).
/// Built from active_phases minus orphaned/terminal phases.
pub fn actual_pipeline_phases() -> Vec<ScanPhase> {
    active_phases()
}

/// Core phases: the set of phases that run under profile="core".
pub fn core_profile_phases() -> Vec<ScanPhase> {
    vec![
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
    ]
}

/// Experimental phases: phases excluded from the core profile.
pub fn experimental_phases() -> Vec<ScanPhase> {
    vec![
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
    ]
}

/// Compute effective phases for a given profile.
/// This is a pure function for testing profile behavior without running a scan.
pub fn effective_phases(profile: ScanPipelineProfile) -> Vec<ScanPhase> {
    match profile {
        ScanPipelineProfile::Core => core_profile_phases(),
        ScanPipelineProfile::All => actual_pipeline_phases(),
    }
}
