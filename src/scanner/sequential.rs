//! Sequential phase execution utilities

use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;

use indicatif::ProgressBar;

use std::time::Instant;

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

/// Execute a single sequential phase with timing and progress reporting
#[allow(dead_code)]
pub async fn execute_sequential_phase(
    scanner: &super::Scanner,
    phase: &ScanPhase,
    findings: Vec<VulnerabilityFinding>,
    pb: &ProgressBar,
    analyzed_files: &[String],
    phase_num: usize,
    total_phases: usize,
) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
    let phase_msg = get_phase_message(phase, phase_num, total_phases);
    pb.set_message(phase_msg);

    let phase_start = Instant::now();

    let (findings, analyzed_files) = scanner
        .run_phase(phase, findings, pb, analyzed_files)
        .await?;

    let phase_duration = phase_start.elapsed();
    tracing::info!("Phase {:?} completed in {:?}", phase, phase_duration);

    Ok((findings, analyzed_files))
}

/// Check if early termination should be triggered
#[allow(dead_code)]
pub fn check_early_termination(findings: &[VulnerabilityFinding], threshold: f32) -> bool {
    threshold > 0.0 && findings.len() as f32 > threshold
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    fn create_test_finding(severity: Severity) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: "test-id".to_string(),
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            severity,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/test.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("unsafe_code()".to_string()),
            diff_hunk: None,
            recommendation: Some("Fix this".to_string()),
            code_location: Some("src/test.rs:42".to_string()),
            already_reported: false,
            sources: vec!["test".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        }
    }

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

    // --- check_early_termination tests ---

    #[test]
    fn test_check_early_termination_below_threshold() {
        let findings = vec![
            create_test_finding(Severity::High),
            create_test_finding(Severity::Medium),
        ];
        // threshold=5, findings=2 -> should not terminate
        assert!(!check_early_termination(&findings, 5.0));
    }

    #[test]
    fn test_check_early_termination_at_threshold() {
        let findings = vec![
            create_test_finding(Severity::High),
            create_test_finding(Severity::Medium),
            create_test_finding(Severity::Low),
        ];
        // threshold=3, findings=3 -> 3.0 > 3.0 is false
        assert!(!check_early_termination(&findings, 3.0));
    }

    #[test]
    fn test_check_early_termination_above_threshold() {
        let findings = vec![
            create_test_finding(Severity::High),
            create_test_finding(Severity::Medium),
            create_test_finding(Severity::Low),
            create_test_finding(Severity::Critical),
        ];
        // threshold=3, findings=4 -> 4.0 > 3.0 is true
        assert!(check_early_termination(&findings, 3.0));
    }

    #[test]
    fn test_check_early_termination_zero_threshold() {
        let findings = vec![create_test_finding(Severity::High)];
        // threshold=0.0 -> should never terminate (disabled)
        assert!(!check_early_termination(&findings, 0.0));
    }

    #[test]
    fn test_check_early_termination_empty_findings() {
        let findings: Vec<VulnerabilityFinding> = vec![];
        // No findings, any positive threshold -> should not terminate
        assert!(!check_early_termination(&findings, 1.0));
    }

    #[test]
    fn test_check_early_termination_negative_threshold() {
        let findings = vec![create_test_finding(Severity::High)];
        // Negative threshold -> should never terminate
        assert!(!check_early_termination(&findings, -1.0));
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
