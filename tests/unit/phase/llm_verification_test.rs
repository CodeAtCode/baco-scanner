#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::create_ctx;
    use baco::create_ctx_with_finding;
    use baco::findings::Severity;
    use baco::phase::helpers::create_test_finding;
    use baco::phase::llm_verification::LlmVerificationPhase;
    use baco::phase::{PhaseContext, ScanPhase};
    use baco::scanner::Scanner;
    use tempfile::TempDir;

    #[test]
    fn test_llm_verification_phase_name_and_order() {
        let phase = LlmVerificationPhase;
        assert_eq!(phase.name(), "LlmVerification");
        assert_eq!(phase.order(), 5);
    }

    #[tokio::test]
    async fn test_llm_verification_phase_with_no_findings() {
        let (_temp_dir, mut ctx) = create_ctx!();

        let phase = LlmVerificationPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_llm_verification_phase_with_findings() {
        let (_temp_dir, mut ctx) =
            create_ctx_with_finding!("Test vulnerability", "test.rs", 42, Severity::High);

        let phase = LlmVerificationPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn test_llm_verification_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let findings = vec![
            create_test_finding("High severity", "high.rs", 10, Severity::High),
            create_test_finding("Medium severity", "medium.rs", 20, Severity::Medium),
            create_test_finding("Low severity", "low.rs", 30, Severity::Low),
        ];

        scanner.state.send_modify(|s| {
            s.findings = findings;
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmVerificationPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let processed_findings = result.unwrap();
        assert_eq!(processed_findings.len(), 3);
    }

    #[tokio::test]
    async fn test_llm_verification_phase_disabled() {
        let (_temp_dir, mut ctx) = create_ctx!();

        let phase = LlmVerificationPhase;
        assert!(!phase.is_enabled(&ctx));

        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
    }
}
