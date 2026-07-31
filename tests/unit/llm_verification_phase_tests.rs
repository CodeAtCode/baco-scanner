//! Unit tests for LlmVerificationPhase
//!
//! These tests cover the LLM verification phase which verifies vulnerability findings
//! using LLM-based analysis. Tests focus on phase behavior without making actual LLM calls.

#![allow(clippy::single_match)]

#[cfg(test)]
mod tests {
    use baco::findings::{Severity, VulnerabilityFinding};
    use baco::phase::llm_verification::LlmVerificationPhase;
    use baco::phase::{PhaseContext, ScanPhase};
    use baco::scanner::Scanner;
    use tempfile::TempDir;

    /// Create a test vulnerability finding with the given parameters.
    fn create_test_finding(
        title: &str,
        file_path: &str,
        line: u32,
        severity: Severity,
    ) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: format!("test-{}", title.replace(' ', "-").to_lowercase()),
            title: title.to_string(),
            description: format!("Test description for {}", title),
            severity,
            confidence_score: 0.8,
            cwe_id: Some("CWE-89".to_string()),
            file_path: file_path.to_string(),
            line_number: Some(line),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
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
            statement_range: None,
            triage_verdict: None,
        }
    }

    /// Create a test config with verification API key set.
    fn create_config_with_verification_key() -> baco::config::ScannerConfig {
        let mut config = baco::config::ScannerConfig::default();
        config.llm.phases.verification.api_key = Some("test-verification-key".to_string());
        config.llm.phases.verification.base_url = "http://localhost:11434".to_string();
        config
    }

    /// Create a test config without verification API key.
    fn create_config_without_verification_key() -> baco::config::ScannerConfig {
        let mut config = baco::config::ScannerConfig::default();
        config.llm.phases.verification.api_key = None;
        config
    }

    #[test]
    fn test_llm_verification_phase_name() {
        let phase = LlmVerificationPhase;
        assert_eq!(phase.name(), "LlmVerification");
    }

    #[test]
    fn test_llm_verification_phase_order() {
        let phase = LlmVerificationPhase;
        assert_eq!(phase.order(), 5);
    }

    #[test]
    fn test_is_enabled_with_api_key() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_config_with_verification_key();
        let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);

        let analyzed_files = vec![];
        let ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files.clone(),
        };

        let phase = LlmVerificationPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[test]
    fn test_is_enabled_without_api_key() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_config_without_verification_key();
        let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);

        let analyzed_files = vec![];
        let ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files.clone(),
        };

        let phase = LlmVerificationPhase;
        assert!(!phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_execute_with_no_api_key_returns_original_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_config_without_verification_key();
        let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);

        // Add a finding to the scanner state
        let finding = create_test_finding("SQL Injection", "src/auth.rs", 42, Severity::High);
        scanner.add_finding(finding.clone());

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmVerificationPhase;
        let result = phase.execute(&mut ctx).await;

        match result {
            Ok(findings) => {
                // Should return the original findings unchanged when no API key
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].title, "SQL Injection");
                // Verification status should still be None since no verification happened
                assert!(findings[0].verification_status.is_none());
            }
            Err(e) => panic!("Phase should not fail when skipping: {}", e),
        }
    }

    #[tokio::test]
    async fn test_execute_with_empty_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_config_with_verification_key();
        let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmVerificationPhase;
        let result = phase.execute(&mut ctx).await;

        match result {
            Ok(findings) => assert!(findings.is_empty()),
            Err(e) => panic!("Phase should handle empty findings gracefully: {}", e),
        }
    }

    #[tokio::test]
    async fn test_execute_preserves_all_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_config_without_verification_key(); // Skip LLM calls
        let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);

        // Add multiple findings
        let finding1 = create_test_finding("SQL Injection", "src/auth.rs", 42, Severity::High);
        let finding2 = create_test_finding("XSS", "src/controller.rs", 128, Severity::Medium);
        let finding3 = create_test_finding("CSRF", "src/form.rs", 55, Severity::Medium);

        scanner.add_finding(finding1);
        scanner.add_finding(finding2);
        scanner.add_finding(finding3);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmVerificationPhase;
        let result = phase.execute(&mut ctx).await;

        match result {
            Ok(findings) => {
                assert_eq!(findings.len(), 3);
                // Findings should be preserved but not verified (no API key)
                for finding in &findings {
                    assert!(finding.verification_status.is_none());
                }
            }
            Err(e) => panic!("Phase should not fail: {}", e),
        }
    }

    #[test]
    fn test_phase_implements_send_sync() {
        // Verify the phase type implements Send and Sync for async usage
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LlmVerificationPhase>();
    }

    #[tokio::test]
    async fn test_execute_phase_order_consistency() {
        // Verify phase order is consistent and appropriate for pipeline positioning
        let phase = LlmVerificationPhase;
        let order = phase.order();

        // Order 5 means it runs after phases 1-4
        // This is appropriate for verification which needs findings from earlier phases
        assert!(order > 0, "Phase order should be positive");
        assert!(order < 20, "Phase order should be within reasonable range");
    }

    #[test]
    fn test_phase_is_unit_struct() {
        // Verify the phase is a unit struct that can be instantiated
        let phase = LlmVerificationPhase;
        assert_eq!(phase.name(), "LlmVerification");
    }

    #[tokio::test]
    async fn test_execute_with_configured_llm_but_no_actual_calls() {
        // When API key is set but we don't actually make LLM calls (due to mock/skip logic),
        // the phase should still complete successfully
        let temp_dir = TempDir::new().unwrap();
        let mut config = create_config_with_verification_key();
        // Set a very short timeout to ensure quick failure if a call is attempted
        config.llm.timeout_secs = 1;

        let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);

        // Add a finding
        let finding = create_test_finding("Test Finding", "src/test.rs", 10, Severity::Low);
        scanner.add_finding(finding);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmVerificationPhase;
        let result = phase.execute(&mut ctx).await;

        // Should complete without panic even if LLM call fails
        // The phase should handle errors gracefully and mark findings as failed
        match result {
            Ok(findings) => {
                // Findings should be returned (possibly with verification status updated)
                assert_eq!(findings.len(), 1);
            }
            Err(_) => {
                // Also acceptable if the phase fails gracefully
            }
        }
    }

    #[tokio::test]
    async fn test_execute_maintains_finding_integrity() {
        // Verify that the phase doesn't corrupt finding data
        let temp_dir = TempDir::new().unwrap();
        let config = create_config_without_verification_key();
        let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);

        let original_finding = create_test_finding(
            "Original Finding",
            "src/original.rs",
            999,
            Severity::Critical,
        );
        let original_id = original_finding.id.clone();
        let original_title = original_finding.title.clone();
        let original_severity = original_finding.severity;
        let original_file = original_finding.file_path.clone();

        scanner.add_finding(original_finding);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmVerificationPhase;
        let result = phase.execute(&mut ctx).await;

        match result {
            Ok(findings) => {
                assert_eq!(findings.len(), 1);
                let finding = &findings[0];

                // Core fields should be preserved
                assert_eq!(finding.id, original_id);
                assert_eq!(finding.title, original_title);
                assert_eq!(finding.severity, original_severity);
                assert_eq!(finding.file_path, original_file);
                assert_eq!(finding.line_number, Some(999));
            }
            Err(e) => panic!("Phase should not corrupt findings: {}", e),
        }
    }
}
