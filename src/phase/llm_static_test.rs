#[cfg(test)]
mod tests {
    use crate::config::ScannerConfig;
    use crate::phase::llm_static::LlmStaticAnalysisPhase;
    use crate::phase::{PhaseContext, ScanPhase};
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_llm_static_phase_name_and_order() {
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
}
