#[cfg(test)]
mod tests {
    use baco::confidence::ConfidenceCalculator;
    use baco::config::ScannerConfig;
    use baco::create_ctx;
    use baco::create_ctx_with_finding;
    use baco::findings::{Severity, VerificationStatus};
    use baco::phase::confidence_scoring::ConfidenceScoringPhase;
    use baco::phase::helpers::create_test_finding;
    use baco::phase::{PhaseContext, ScanPhase};
    use baco::scanner::Scanner;
    use tempfile::TempDir;

    #[test]
    fn test_confidence_scoring_phase_name_and_order() {
        let phase = ConfidenceScoringPhase;
        assert_eq!(phase.name(), "ConfidenceScoring");
        assert_eq!(phase.order(), 9);
    }

    #[tokio::test]
    async fn test_confidence_scoring_phase_with_no_findings() {
        let (_temp_dir, mut ctx) = create_ctx!();

        let phase = ConfidenceScoringPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_confidence_scoring_phase_with_findings() {
        let (_temp_dir, mut ctx) =
            create_ctx_with_finding!("Test vulnerability", "test.rs", 42, Severity::High);

        let phase = ConfidenceScoringPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].confidence_score > 0.0);
    }

    #[tokio::test]
    async fn test_confidence_scoring_multiple_findings() {
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

        let phase = ConfidenceScoringPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let processed_findings = result.unwrap();
        assert_eq!(processed_findings.len(), 3);

        for finding in &processed_findings {
            assert!(finding.confidence_score >= 0.0);
            assert!(finding.confidence_score <= 100.0);
        }
    }

    #[tokio::test]
    async fn test_confidence_scoring_with_multiple_sources() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut finding = create_test_finding("Multi-source", "multi.rs", 15, Severity::Critical);
        finding.sources = vec![
            "semgrep".to_string(),
            "llm".to_string(),
            "manual".to_string(),
        ];

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = ConfidenceScoringPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].confidence_score > 0.0);
    }

    #[test]
    fn test_confidence_calculator_with_single_source() {
        let mut finding = create_test_finding("Single source", "test.rs", 1, Severity::Medium);

        ConfidenceCalculator::recalculate_priority(&mut finding);

        assert!(finding.confidence_score > 0.0);
        assert!(finding.confidence_score <= 100.0);
    }

    #[test]
    fn test_confidence_calculator_with_critical_severity() {
        let mut finding = create_test_finding("Critical", "critical.rs", 1, Severity::Critical);

        ConfidenceCalculator::recalculate_priority(&mut finding);

        assert!(finding.confidence_score >= 50.0);
    }

    #[test]
    fn test_confidence_calculator_with_verified_status() {
        let mut finding = create_test_finding("Verified", "verified.rs", 1, Severity::Medium);
        finding.verification_status = Some(VerificationStatus::Confirmed);

        ConfidenceCalculator::recalculate_priority(&mut finding);

        assert!(finding.confidence_score >= 70.0);
    }
}
