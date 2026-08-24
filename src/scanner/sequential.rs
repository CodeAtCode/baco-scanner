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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- get_phase_message tests ---

    #[test]
    fn test_get_phase_message_llm_discovery() {
        let msg = get_phase_message(&ScanPhase::LlmDiscovery, 1, 16);
        assert!(msg.contains("Phase 1/16"));
        assert!(msg.contains("LLM discovery"));
        assert!(msg.contains("enriching findings"));
    }

    #[test]
    fn test_get_phase_message_llm_verification() {
        let msg = get_phase_message(&ScanPhase::LlmVerification, 2, 16);
        assert!(msg.contains("Phase 2/16"));
        assert!(msg.contains("LLM verification"));
        assert!(msg.contains("validating findings"));
    }

    #[test]
    fn test_get_phase_message_security_agent_verification() {
        let msg = get_phase_message(&ScanPhase::SecurityAgentVerification, 3, 16);
        assert!(msg.contains("Phase 3/16"));
        assert!(msg.contains("SecurityAgent verification"));
        assert!(msg.contains("tool-based validation"));
    }

    #[test]
    fn test_get_phase_message_git_analysis() {
        let msg = get_phase_message(&ScanPhase::GitAnalysis, 5, 16);
        assert!(msg.contains("Phase 5/16"));
        assert!(msg.contains("Analyzing Git history"));
        assert!(msg.contains("related commits"));
    }

    #[test]
    fn test_get_phase_message_threat_modeling() {
        let msg = get_phase_message(&ScanPhase::ThreatModeling, 10, 16);
        assert!(msg.contains("Phase 10/16"));
        assert!(msg.contains("Threat modeling"));
        assert!(msg.contains("STRIDE analysis"));
    }

    #[test]
    fn test_get_phase_message_auto_patching() {
        let msg = get_phase_message(&ScanPhase::AutoPatching, 14, 16);
        assert!(msg.contains("Phase 14/16"));
        assert!(msg.contains("Auto-patching"));
        assert!(msg.contains("staging validation"));
    }

    #[test]
    fn test_get_phase_message_unknown_phase() {
        // Test fallback for phases not explicitly handled
        let msg = get_phase_message(&ScanPhase::Indexing, 0, 16);
        assert!(msg.contains("Phase 0/16"));
        assert!(msg.contains("Indexing"));
    }

    // --- SEQUENTIAL_PHASES constant tests ---

    #[test]
    fn test_sequential_phases_count() {
        // Verify we have exactly 16 phases defined
        assert_eq!(SEQUENTIAL_PHASES.len(), 16);
    }

    #[test]
    fn test_sequential_phases_order() {
        // Verify critical phases are in expected order
        assert_eq!(SEQUENTIAL_PHASES[0], ScanPhase::LlmDiscovery);
        assert_eq!(SEQUENTIAL_PHASES[1], ScanPhase::LlmVerification);
        assert_eq!(SEQUENTIAL_PHASES[8], ScanPhase::Reporting);
    }

    #[test]
    fn test_sequential_phases_contains_all_v3_features() {
        // Verify all v3 features are present
        let phases = SEQUENTIAL_PHASES;
        assert!(phases.contains(&ScanPhase::ThreatModeling));
        assert!(phases.contains(&ScanPhase::RootCauseDedup));
        assert!(phases.contains(&ScanPhase::MultiVerifier));
        assert!(phases.contains(&ScanPhase::AutoPatching));
        assert!(phases.contains(&ScanPhase::CveBootstrap));
        assert!(phases.contains(&ScanPhase::PocCompiler));
        assert!(phases.contains(&ScanPhase::VariantSearch));
    }

    #[test]
    fn test_sequential_phases_no_duplicates() {
        // Ensure no phase appears twice
        let mut unique_phases = std::collections::HashSet::new();
        for phase in SEQUENTIAL_PHASES.iter() {
            assert!(
                unique_phases.insert(phase.clone()),
                "Duplicate phase found: {:?}",
                phase
            );
        }
    }
}
