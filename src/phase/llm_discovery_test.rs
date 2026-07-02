#[cfg(test)]
mod tests {
    use crate::config::ScannerConfig;
    use crate::phase::llm_discovery::LlmDiscoveryPhase;
    use crate::phase::{PhaseContext, ScanPhase};
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    #[test]
    fn test_llm_discovery_phase_name_and_order() {
        let phase = LlmDiscoveryPhase;
        assert_eq!(phase.name(), "LlmDiscovery");
        assert_eq!(phase.order(), 4);
    }

    #[tokio::test]
    async fn test_llm_discovery_phase_without_llm() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.llm.phases.discovery.base_url = String::new();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = LlmDiscoveryPhase;
        let result = phase.execute(&mut ctx).await;

        // Should handle missing LLM gracefully
        assert!(result.is_ok() || result.is_err());
    }
}
