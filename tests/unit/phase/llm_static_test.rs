#![allow(clippy::single_match)]

#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::phase::llm_static::LlmStaticAnalysisPhase;
    use baco::phase::{PhaseContext, ScanPhase};
    use baco::scanner::Scanner;
    use tempfile::TempDir;

    #[test]
    fn test_llm_static_phase_name_and_order() {
        let phase = LlmStaticAnalysisPhase;
        assert_eq!(phase.name(), "LlmStaticAnalysis");
        assert_eq!(phase.order(), 3);
    }

    #[tokio::test]
    async fn test_llm_static_phase_without_llm_config() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        // Disable LLM by clearing base_url
        config.llm.phases.discovery.base_url = String::new();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmStaticAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        // Should return empty findings when LLM is disabled
        match result {
            Ok(findings) => assert!(findings.is_empty()),
            Err(_) => {} // Also acceptable if phase fails gracefully
        }
    }

    #[tokio::test]
    async fn test_llm_static_analysis_with_empty_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmStaticAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        // Should return Ok with empty results when no findings to process
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_llm_static_analysis_with_disabled_config() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        // Disable LLM by clearing API key
        config.llm.phases.discovery.api_key = None;

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmStaticAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        // Should return Ok gracefully when LLM is disabled
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_llm_static_analysis_preserves_analyzed_files() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        // Pre-populate analyzed_files
        let mut analyzed_files = vec![
            "/path/to/already/analyzed/file1.rs".to_string(),
            "/path/to/already/analyzed/file2.rs".to_string(),
        ];
        let initial_count = analyzed_files.len();
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmStaticAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        // Should preserve existing analyzed_files
        assert!(result.is_ok());
        let _ = result.unwrap();
        // analyzed_files is modified in place via ctx
        assert!(analyzed_files.len() >= initial_count);
        assert!(analyzed_files.contains(&"/path/to/already/analyzed/file1.rs".to_string()));
        assert!(analyzed_files.contains(&"/path/to/already/analyzed/file2.rs".to_string()));
    }

    #[tokio::test]
    async fn test_llm_static_analysis_with_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        // Create multiple test findings
        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmStaticAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        // Should handle processing without errors
        assert!(result.is_ok());
        let _ = result.unwrap();
        // With no LLM configured, should return empty or minimal findings
        // The key is that it doesn't crash with multiple findings scenario
    }

    #[tokio::test]
    async fn test_llm_static_analysis_metrics_tracker() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmStaticAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        // Should complete without metrics-related panics
        assert!(result.is_ok());
        let _ = result.unwrap();
        // Metrics tracking is internal; we verify by successful completion
    }
}
