#[cfg(test)]
mod tests {
    use crate::config::ScannerConfig;
    use crate::create_ctx;
    use crate::crossfile::CrossFileAnalyzer;
    use crate::findings::{Severity, VulnerabilityFinding};
    use crate::phase::cross_file_analysis::CrossFileAnalysisPhase;
    use crate::phase::helpers::create_test_finding;
    use crate::phase::{PhaseContext, ScanPhase};
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cross_file_analysis_phase_name_and_order() {
        let phase = CrossFileAnalysisPhase;
        assert_eq!(phase.name(), "CrossFileAnalysis");
        assert_eq!(phase.order(), 8);
    }

    #[tokio::test]
    async fn test_cross_file_analysis_phase_with_no_findings() {
        let (_temp_dir, mut ctx) = create_ctx!();

        let phase = CrossFileAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_cross_file_analysis_phase_with_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding =
            create_test_finding("Cross-file vulnerability", "main.rs", 10, Severity::High);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = CrossFileAnalysisPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_cross_file_analyzer_empty_findings() {
        let findings: Vec<VulnerabilityFinding> = vec![];
        let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);
        assert!(result.is_empty());
    }

    #[test]
    fn test_cross_file_analyzer_single_finding() {
        let finding = create_test_finding("Single finding", "test.rs", 5, Severity::Medium);
        let findings = vec![finding];
        let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_cross_file_analyzer_multiple_findings() {
        let findings = vec![
            create_test_finding("Finding 1", "file1.rs", 10, Severity::High),
            create_test_finding("Finding 2", "file2.rs", 20, Severity::Medium),
            create_test_finding("Finding 3", "file3.rs", 30, Severity::Low),
        ];

        let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_cross_file_analyzer_preserves_finding_data() {
        let finding = create_test_finding("Preserve test", "preserve.rs", 42, Severity::Critical);
        let original_title = finding.title.clone();
        let original_path = finding.file_path.clone();
        let original_severity = finding.severity;

        let findings = vec![finding];
        let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

        assert_eq!(result[0].title, original_title);
        assert_eq!(result[0].file_path, original_path);
        assert_eq!(result[0].severity, original_severity);
    }

    #[tokio::test]
    async fn test_cross_file_analysis_is_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = CrossFileAnalysisPhase;
        assert!(phase.is_enabled(&ctx));
    }
}
