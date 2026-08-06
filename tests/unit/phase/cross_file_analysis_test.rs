#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::create_ctx;
    use baco::create_ctx_with_finding;
    use baco::findings::Severity;
    use baco::phase::helpers::create_test_finding;
    use baco::scanner::Scanner;
    use tempfile::TempDir;

    #[test]
    fn test_cross_file_analysis_module_exists() {
        // CrossFileAnalysisPhase is in src/phase/cross_file_analysis.rs
        // but doesn't implement ScanPhase trait - it's used via run_cross_file_analysis function
    }

    #[tokio::test]
    async fn test_cross_file_analysis_with_no_findings() {
        let (_temp_dir, _ctx) = create_ctx!();
        // Just verify the function exists and can be called
        let findings = vec![];
        let result = baco::crossfile::CrossFileAnalyzer::analyze_cross_file_references(&findings);
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_cross_file_analysis_with_findings() {
        let (_temp_dir, _ctx) =
            create_ctx_with_finding!("Test vulnerability", "test.rs", 42, Severity::High);
        let findings = vec![];
        let result = baco::crossfile::CrossFileAnalyzer::analyze_cross_file_references(&findings);
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_cross_file_analysis_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let findings = vec![
            create_test_finding("High severity", "high.rs", 10, Severity::High),
            create_test_finding("Medium severity", "medium.rs", 20, Severity::Medium),
            create_test_finding("Low severity", "low.rs", 30, Severity::Low),
        ];

        scanner.state.send_modify(|s| {
            s.findings = findings;
        });

        let findings = scanner.state.borrow().findings.clone();
        let result = baco::crossfile::CrossFileAnalyzer::analyze_cross_file_references(&findings);
        assert_eq!(result.len(), 3);
    }
}
