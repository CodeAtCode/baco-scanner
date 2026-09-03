//! Sequential phase execution utilities

use crate::checkpoint::ScanPhase;

/// List of all sequential phases in execution order
#[allow(dead_code)]
pub const SEQUENTIAL_PHASES: [ScanPhase; 16] = [
    ScanPhase::LlmDiscovery,
    ScanPhase::LlmVerification,
    ScanPhase::SecurityAgentVerification,
    ScanPhase::TicketCrossRef,
    ScanPhase::GitAnalysis,
    ScanPhase::CrossFileAnalysis,
    ScanPhase::ConfidenceScoring,
    ScanPhase::AiAggregation,
    ScanPhase::Reporting,
    // v3 features
    ScanPhase::ThreatModeling,
    ScanPhase::RootCauseDedup,
    ScanPhase::MultiVerifier,
    ScanPhase::AutoPatching,
    ScanPhase::CveBootstrap,
    ScanPhase::PocCompiler,
    ScanPhase::VariantSearch,
];

/// Get phase message for progress bar
#[allow(dead_code)]
pub fn get_phase_message(phase: &ScanPhase, phase_num: usize, total_phases: usize) -> String {
    match phase {
        ScanPhase::LlmDiscovery => format!(
            "Phase {}/{}: LLM discovery (enriching findings with context)...",
            phase_num, total_phases
        ),
        ScanPhase::LlmVerification => format!(
            "Phase {}/{}: LLM verification (validating findings)...",
            phase_num, total_phases
        ),
        ScanPhase::SecurityAgentVerification => format!(
            "Phase {}/{}: SecurityAgent verification (tool-based validation)...",
            phase_num, total_phases
        ),
        ScanPhase::TicketCrossRef => format!(
            "Phase {}/{}: Searching ticket systems for references...",
            phase_num, total_phases
        ),
        ScanPhase::GitAnalysis => format!(
            "Phase {}/{}: Analyzing Git history for related commits...",
            phase_num, total_phases
        ),
        ScanPhase::CrossFileAnalysis => format!(
            "Phase {}/{}: Cross-file dependency analysis...",
            phase_num, total_phases
        ),
        ScanPhase::ConfidenceScoring => format!(
            "Phase {}/{}: Calculating confidence scores...",
            phase_num, total_phases
        ),
        ScanPhase::AiAggregation => format!(
            "Phase {}/{}: AI aggregation (generating executive summary)...",
            phase_num, total_phases
        ),
        ScanPhase::Reporting => format!(
            "Phase {}/{}: Generating reports (JSON/HTML/SARIF)...",
            phase_num, total_phases
        ),
        ScanPhase::ThreatModeling => format!(
            "Phase {}/{}: Threat modeling (STRIDE analysis)...",
            phase_num, total_phases
        ),
        ScanPhase::RootCauseDedup => format!(
            "Phase {}/{}: Root cause deduplication...",
            phase_num, total_phases
        ),
        ScanPhase::MultiVerifier => format!(
            "Phase {}/{}: Multi-verifier voting...",
            phase_num, total_phases
        ),
        ScanPhase::AutoPatching => format!(
            "Phase {}/{}: Auto-patching with staging validation...",
            phase_num, total_phases
        ),
        ScanPhase::CveBootstrap => {
            format!("Phase {}/{}: CVE bootstrap...", phase_num, total_phases)
        }
        ScanPhase::PocCompiler => format!(
            "Phase {}/{}: PoC compilation check...",
            phase_num, total_phases
        ),
        ScanPhase::VariantSearch => {
            format!("Phase {}/{}: Variant search...", phase_num, total_phases)
        }
        _ => format!("Phase {}/{}: {:?}", phase_num, total_phases, phase),
    }
}

// ============================================================================
