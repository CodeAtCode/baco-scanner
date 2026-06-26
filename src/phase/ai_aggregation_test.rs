#[cfg(test)]
mod tests {
    use crate::config::ScannerConfig;
    use crate::findings::Severity;
    use crate::phase::ai_aggregation::AiAggregationPhase;
    use crate::phase::helpers::create_test_finding;
    use crate::phase::{PhaseContext, ScanPhase};
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_ai_aggregation_phase_name_and_order() {
        let phase = AiAggregationPhase;
        assert_eq!(phase.name(), "AiAggregation");
        assert_eq!(phase.order(), 10);
    }

    #[tokio::test]
    async fn test_ai_aggregation_phase_with_no_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.llm.phases.aggregation.api_key = Some("test-key".to_string());
        config.llm.phases.aggregation.base_url = "http://localhost:8080".to_string();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = AiAggregationPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_ai_aggregation_phase_without_llm_config() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("Test finding", "test.rs", 10, Severity::Medium);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = AiAggregationPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn test_ai_aggregation_phase_is_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = AiAggregationPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_ai_aggregation_phase_with_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.llm.phases.aggregation.api_key = Some("test-key".to_string());
        config.llm.phases.aggregation.base_url = "http://localhost:8080".to_string();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let findings = vec![
            create_test_finding("Finding 1", "file1.rs", 1, Severity::Critical),
            create_test_finding("Finding 2", "file2.rs", 10, Severity::High),
        ];

        scanner.state.send_modify(|s| {
            s.findings = findings;
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = AiAggregationPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let processed_findings = result.unwrap();
        assert_eq!(processed_findings.len(), 2);
    }
}
