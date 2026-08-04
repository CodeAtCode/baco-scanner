//! Tests extracted from the inline `#[cfg(test)] mod tests` block of
//! `src/scanner/orchestrator.rs`.
//!
//! These tests were moved out of the orchestrator module. The orchestrator
//! module is private (`mod orchestrator;` in `src/scanner/mod.rs`), so its
//! private items — the `PhaseResult` type alias and the `sequential_phases()`
//! function — are not reachable from this external test file. Tests that
//! referenced those private items are preserved below but commented out.

#![allow(clippy::useless_vec)]

#[cfg(test)]
mod tests {
    use baco::checkpoint::ScanPhase;
    use baco::findings::{Severity, VulnerabilityFinding};

    // NOTE: `test_phase_result_type` references the private type alias
    // `PhaseResult` defined in `src/scanner/orchestrator.rs`. The orchestrator
    // module is private, so `PhaseResult` is not accessible here. Test kept for
    // reference; re-enable if `PhaseResult` is ever exposed publicly.
    /*
    #[test]
    fn test_phase_result_type() {
        let result: PhaseResult = Ok((vec![], vec![]));
        assert!(result.is_ok());
    }
    */

    #[test]
    fn test_checkpoint_findings_loading_logic_empty() {
        let checkpoint_findings: Vec<VulnerabilityFinding> = vec![];
        let has_valid_findings = !checkpoint_findings.is_empty()
            && checkpoint_findings
                .iter()
                .any(|f| !f.description.is_empty());

        assert!(!has_valid_findings);
    }

    #[test]
    fn test_checkpoint_findings_with_empty_descriptions() {
        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: String::new(),
            severity: Severity::Low,
            confidence_score: 0.5,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            cwe_id: None,
            verification_status: None,
            sources: vec![],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
        }];

        let has_valid = findings.iter().all(|f| f.description.is_empty());

        assert!(has_valid);
    }

    #[test]
    fn test_checkpoint_findings_logic_with_valid_data() {
        let valid_finding = VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Valid description".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            file_path: "src/main.rs".to_string(),
            line_number: Some(42),
            code_snippet: None,
            cwe_id: Some("CWE-79".to_string()),
            verification_status: None,
            sources: vec!["semgrep".to_string()],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
        };

        let checkpoint_findings = vec![valid_finding];
        let has_valid_findings = !checkpoint_findings.is_empty()
            && checkpoint_findings
                .iter()
                .any(|f| !f.description.is_empty());

        assert!(has_valid_findings);
    }

    #[test]
    fn test_checkpoint_findings_mixed_valid_invalid() {
        let findings = vec![
            VulnerabilityFinding {
                id: "test-1".to_string(),
                title: "Empty desc".to_string(),
                description: String::new(),
                severity: Severity::Low,
                confidence_score: 0.3,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                cwe_id: None,
                verification_status: None,
                sources: vec![],
                cross_file_references: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
                statement_range: None,
                triage_verdict: None,
            },
            VulnerabilityFinding {
                id: "test-2".to_string(),
                title: "Valid".to_string(),
                description: "Has description".to_string(),
                severity: Severity::Medium,
                confidence_score: 0.6,
                file_path: "src/lib.rs".to_string(),
                line_number: Some(10),
                code_snippet: None,
                cwe_id: None,
                verification_status: None,
                sources: vec![],
                cross_file_references: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
                statement_range: None,
                triage_verdict: None,
            },
        ];

        let has_valid = !findings.is_empty() && findings.iter().any(|f| !f.description.is_empty());

        assert!(has_valid);
    }

    // NOTE: `test_sequential_phases_array_length` references the private
    // function `sequential_phases()` defined in `src/scanner/orchestrator.rs`.
    // The orchestrator module is private, so this function is not accessible
    // here. Test kept for reference; re-enable if `sequential_phases` is ever
    // exposed publicly.
    /*
    #[test]
    fn test_sequential_phases_array_length() {
        let sequential_phases = sequential_phases();
        assert_eq!(sequential_phases.len(), 17);
    }
    */

    // NOTE: `test_sequential_phases_contains_expected_phases` references the
    // private function `sequential_phases()`. See note above.
    /*
    #[test]
    fn test_sequential_phases_contains_expected_phases() {
        let sequential_phases = sequential_phases();

        assert!(sequential_phases.contains(&ScanPhase::LlmDiscovery));
        assert!(sequential_phases.contains(&ScanPhase::LlmVerification));
        assert!(sequential_phases.contains(&ScanPhase::Reporting));
        assert!(sequential_phases.contains(&ScanPhase::ThreatModeling));
        assert!(sequential_phases.contains(&ScanPhase::VariantSearch));
    }
    */

    // NOTE: `test_phase_ordering_first_phase` references the private function
    // `sequential_phases()`. See note above.
    /*
    #[test]
    fn test_phase_ordering_first_phase() {
        let sequential_phases = sequential_phases();

        assert_eq!(sequential_phases[0], ScanPhase::CweRouting);
        assert_eq!(
            sequential_phases[sequential_phases.len() - 1],
            ScanPhase::Reporting
        );
    }
    */

    #[test]
    fn test_total_phases_calculation() {
        let enable_parallel = true;
        let sequential_phase_count = 17;
        let total_phases = 3 + sequential_phase_count;

        assert_eq!(total_phases, 20);
        assert!(enable_parallel);
    }

    #[test]
    fn test_start_position_based_on_parallel() {
        let enable_parallel = true;
        let start_position = if enable_parallel { 300 } else { 0 };
        assert_eq!(start_position, 300);

        let enable_parallel_false = false;
        let start_position_no_parallel = if enable_parallel_false { 300 } else { 0 };
        assert_eq!(start_position_no_parallel, 0);
    }

    #[test]
    fn test_phase_num_calculation() {
        let sequential_phases = [
            ScanPhase::CweRouting,
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
        ];

        for (i, phase) in sequential_phases.iter().enumerate() {
            let phase_num = 4 + i;
            assert!(phase_num >= 4);
            let _ = phase; // Suppress unused warning
        }
    }

    // NOTE: `test_phase_message_formatting` references the private function
    // `sequential_phases()`. See note above.
    /*
    #[test]
    fn test_phase_message_formatting() {
        let sequential_phases = sequential_phases();

        for (i, phase) in sequential_phases.iter().enumerate() {
            let phase_num = 4 + i;
            let total = sequential_phases.len() + 3;

            let phase_msg = match phase {
                ScanPhase::CweRouting => format!(
                    "Phase {}/{}: CWE routing (routing findings to specialized models)...",
                    phase_num, total
                ),
                ScanPhase::LlmDiscovery => format!(
                    "Phase {}/{}: LLM discovery (enriching findings with context)...",
                    phase_num, total
                ),
                ScanPhase::LlmVerification => format!(
                    "Phase {}/{}: LLM verification (validating findings)...",
                    phase_num, total
                ),
                ScanPhase::SecurityAgentVerification => format!(
                    "Phase {}/{}: SecurityAgent verification (tool-based validation)...",
                    phase_num, total
                ),
                ScanPhase::TicketCrossRef => format!(
                    "Phase {}/{}: Searching ticket systems for references...",
                    phase_num, total
                ),
                ScanPhase::GitAnalysis => format!(
                    "Phase {}/{}: Analyzing Git history for related commits...",
                    phase_num, total
                ),
                ScanPhase::CrossFileAnalysis => format!(
                    "Phase {}/{}: Cross-file dependency analysis...",
                    phase_num, total
                ),
                ScanPhase::ConfidenceScoring => format!(
                    "Phase {}/{}: Calculating confidence scores...",
                    phase_num, total
                ),
                ScanPhase::AiAggregation => format!(
                    "Phase {}/{}: AI aggregation (generating executive summary)...",
                    phase_num, total
                ),
                ScanPhase::ThreatModeling => format!(
                    "Phase {}/{}: Threat modeling (STRIDE analysis)...",
                    phase_num, total
                ),
                ScanPhase::RootCauseDedup => {
                    format!("Phase {}/{}: Root cause deduplication...", phase_num, total)
                }
                ScanPhase::MultiVerifier => {
                    format!("Phase {}/{}: Multi-verifier voting...", phase_num, total)
                }
                ScanPhase::AutoPatching => format!(
                    "Phase {}/{}: Auto-patching with staging validation...",
                    phase_num, total
                ),
                ScanPhase::CveBootstrap => {
                    format!("Phase {}/{}: CVE bootstrap...", phase_num, total)
                }
                ScanPhase::PocCompiler => {
                    format!("Phase {}/{}: PoC compilation check...", phase_num, total)
                }
                ScanPhase::VariantSearch => {
                    format!("Phase {}/{}: Variant search...", phase_num, total)
                }
                ScanPhase::Reporting => format!(
                    "Phase {}/{}: Generating reports (JSON/HTML/SARIF)...",
                    phase_num, total
                ),
                _ => format!("Phase {}/{}: {:?}", phase_num, total, phase),
            };

            assert!(!phase_msg.is_empty());
            assert!(phase_msg.contains("Phase"));
        }
    }
    */

    #[test]
    fn test_early_termination_threshold_logic() {
        let threshold: f32 = 100.0;
        let findings_count = 50;

        assert!(!(threshold > 0.0 && findings_count as f32 > threshold));

        let findings_above = 150;
        assert!(threshold > 0.0 && findings_above as f32 > threshold);

        let threshold_disabled: f32 = 0.0;
        assert!(!(threshold_disabled > 0.0 && findings_count as f32 > threshold_disabled));
    }

    #[test]
    fn test_completed_phases_check() {
        let completed_phases = vec![ScanPhase::Indexing, ScanPhase::Semgrep];
        let is_phase_completed = |phase: &ScanPhase| completed_phases.contains(phase);

        assert!(is_phase_completed(&ScanPhase::Indexing));
        assert!(is_phase_completed(&ScanPhase::Semgrep));
        assert!(!is_phase_completed(&ScanPhase::LlmDiscovery));
        assert!(!is_phase_completed(&ScanPhase::Reporting));
    }

    #[test]
    fn test_checkpoint_position_calculation() {
        let start_position = 300;
        let phase_index = 0;
        let position = start_position + (phase_index as u64) * 100;
        assert_eq!(position, 300);

        let phase_index_5 = 5;
        let position_5 = start_position + (phase_index_5 as u64) * 100;
        assert_eq!(position_5, 800);

        let phase_index_last = 15;
        let position_last = start_position + (phase_index_last as u64) * 100;
        assert_eq!(position_last, 1800);
    }

    #[test]
    fn test_parallel_phase_result_aggregation() {
        let mut findings: Vec<VulnerabilityFinding> = vec![];
        let mut analyzed_files: Vec<String> = vec![];

        let indexing_findings = vec![VulnerabilityFinding {
            id: "index-1".to_string(),
            title: "Index finding".to_string(),
            description: "From indexing".to_string(),
            severity: Severity::Low,
            confidence_score: 0.4,
            file_path: "index.rs".to_string(),
            line_number: None,
            code_snippet: None,
            cwe_id: None,
            verification_status: None,
            sources: vec![],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
        }];

        findings.append(&mut indexing_findings.clone());
        assert_eq!(findings.len(), 1);

        let semgrep_findings = vec![VulnerabilityFinding {
            id: "semgrep-1".to_string(),
            title: "Semgrep finding".to_string(),
            description: "From semgrep".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            file_path: "semgrep.rs".to_string(),
            line_number: Some(42),
            code_snippet: None,
            cwe_id: Some("CWE-89".to_string()),
            verification_status: None,
            sources: vec!["semgrep".to_string()],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
        }];

        findings.append(&mut semgrep_findings.clone());
        assert_eq!(findings.len(), 2);

        analyzed_files = vec!["file1.rs".to_string(), "file2.rs".to_string()];
        assert_eq!(analyzed_files.len(), 2);
    }

    #[test]
    fn test_force_flag_logic() {
        let force_true = true;
        let force_false = false;

        let (findings_force, completed_force, files_force): (
            Vec<VulnerabilityFinding>,
            Vec<ScanPhase>,
            Vec<String>,
        ) = if force_true {
            (Vec::new(), Vec::new(), Vec::new())
        } else {
            (vec![], vec![], vec![])
        };

        assert!(findings_force.is_empty());
        assert!(completed_force.is_empty());
        assert!(files_force.is_empty());

        let (_, _, _): (Vec<i32>, Vec<i32>, Vec<i32>) = if force_false {
            (Vec::new(), Vec::new(), Vec::new())
        } else {
            (vec![1], vec![2], vec![3])
        };
    }

    #[test]
    fn test_progress_bar_position_updates() {
        let start_position = 300;
        let phase_count = 17;

        for i in 0..phase_count {
            let position = start_position + (i as u64) * 100;
            assert!(position >= 300);
            assert!(position <= 2000);
        }
    }

    #[test]
    fn test_phase_completion_state_update() {
        let phase = ScanPhase::LlmStaticAnalysis;
        let findings_count = 5;

        let current_phase = phase.clone();
        assert_eq!(current_phase, ScanPhase::LlmStaticAnalysis);

        let _findings = vec!["finding1"; findings_count];
        assert_eq!(_findings.len(), 5);
    }

    #[test]
    fn test_phase_skip_logic() {
        let completed_phases = vec![
            ScanPhase::Indexing,
            ScanPhase::Semgrep,
            ScanPhase::LlmDiscovery,
        ];
        let phases_to_run = [
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
            ScanPhase::GitAnalysis,
        ];

        let mut skipped = 0;
        let mut executed = 0;

        for phase in phases_to_run.iter() {
            if completed_phases.contains(phase) {
                skipped += 1;
            } else {
                executed += 1;
            }
        }

        assert_eq!(skipped, 1);
        assert_eq!(executed, 2);
    }

    #[test]
    fn test_scanner_force_checkpoint_ignore() {
        let force = true;
        let checkpoint_exists = true;

        let should_ignore_checkpoint = force;
        assert!(should_ignore_checkpoint);

        let (findings, completed, files) = if force {
            (Vec::new(), Vec::new(), Vec::new())
        } else if checkpoint_exists {
            (vec![1], vec![2], vec![3])
        } else {
            (vec![], vec![], vec![])
        };

        assert!(findings.is_empty());
        assert!(completed.is_empty());
        assert!(files.is_empty());
    }

    // NOTE: `test_phase_result_type_variants` references the private type alias
    // `PhaseResult` defined in `src/scanner/orchestrator.rs`. The orchestrator
    // module is private, so `PhaseResult` is not accessible here. Test kept for
    // reference; re-enable if `PhaseResult` is ever exposed publicly.
    /*
    #[test]
    fn test_phase_result_type_variants() {
        let ok_result: PhaseResult = Ok((vec![], vec![]));
        assert!(ok_result.is_ok());

        let ok_with_data: PhaseResult = Ok((
            vec![VulnerabilityFinding {
                id: "test".to_string(),
                title: "Test".to_string(),
                description: "Desc".to_string(),
                severity: Severity::Low,
                confidence_score: 0.5,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                cwe_id: None,
                verification_status: None,
                sources: vec![],
                cross_file_references: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
                statement_range: None,
                triage_verdict: None,
            }],
            vec!["file.rs".to_string()],
        ));
        assert!(ok_with_data.is_ok());
        if let Ok((findings, files)) = ok_with_data {
            assert_eq!(findings.len(), 1);
            assert_eq!(files.len(), 1);
        }

        let err_result: PhaseResult = Err("error message".to_string());
        assert!(err_result.is_err());
        if let Err(msg) = err_result {
            assert_eq!(msg, "error message");
        }
    }
    */

    #[test]
    fn test_checkpoint_findings_boundary_conditions() {
        let empty: Vec<VulnerabilityFinding> = vec![];
        let has_valid_empty = !empty.is_empty() && empty.iter().any(|f| !f.description.is_empty());
        assert!(!has_valid_empty);

        let single_empty_desc = vec![VulnerabilityFinding {
            id: "test".to_string(),
            title: "Test".to_string(),
            description: String::new(),
            severity: Severity::Low,
            confidence_score: 0.5,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            cwe_id: None,
            verification_status: None,
            sources: vec![],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
        }];
        let has_valid_single = !single_empty_desc.is_empty()
            && single_empty_desc.iter().any(|f| !f.description.is_empty());
        assert!(!has_valid_single);
    }

    #[test]
    fn test_early_termination_message_formatting() {
        let threshold: f32 = 100.0;
        let findings_count = 150;

        let msg = format!(
            "Early termination: {} findings (threshold: {})",
            findings_count, threshold
        );

        assert!(msg.contains("150"));
        assert!(msg.contains("100"));
        assert!(msg.contains("Early termination"));
    }

    #[test]
    fn test_phase_message_for_all_sequential_phases() {
        let phases = [
            (ScanPhase::CweRouting, "CWE routing"),
            (ScanPhase::LlmDiscovery, "LLM discovery"),
            (ScanPhase::LlmVerification, "LLM verification"),
            (
                ScanPhase::SecurityAgentVerification,
                "SecurityAgent verification",
            ),
            (ScanPhase::TicketCrossRef, "Searching ticket systems"),
            (ScanPhase::GitAnalysis, "Analyzing Git history"),
            (ScanPhase::CrossFileAnalysis, "Cross-file dependency"),
            (
                ScanPhase::ConfidenceScoring,
                "Calculating confidence scores",
            ),
            (ScanPhase::AiAggregation, "AI aggregation"),
            (ScanPhase::ThreatModeling, "Threat modeling"),
            (ScanPhase::RootCauseDedup, "Root cause deduplication"),
            (ScanPhase::MultiVerifier, "Multi-verifier voting"),
            (ScanPhase::AutoPatching, "Auto-patching"),
            (ScanPhase::CveBootstrap, "CVE bootstrap"),
            (ScanPhase::PocCompiler, "PoC compilation"),
            (ScanPhase::VariantSearch, "Variant search"),
            (ScanPhase::Reporting, "Generating reports"),
        ];

        for (phase, expected_text) in phases.iter() {
            let msg = match phase {
                ScanPhase::CweRouting => "CWE routing (routing findings to specialized models)...",
                ScanPhase::LlmDiscovery => "LLM discovery (enriching findings with context)...",
                ScanPhase::LlmVerification => "LLM verification (validating findings)...",
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
                ScanPhase::VariantSearch => "Variant search...",
                ScanPhase::Reporting => "Generating reports (JSON/HTML/SARIF)...",
                _ => "unknown",
            };

            assert!(
                msg.contains(*expected_text),
                "Phase {:?} message mismatch",
                phase
            );
        }
    }
}
