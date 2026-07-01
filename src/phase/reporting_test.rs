#[cfg(test)]
mod tests {
    use crate::config::ScannerConfig;
    use crate::findings::Severity;
    use crate::phase::helpers::create_test_finding;
    use crate::phase::reporting::ReportingPhase;
    use crate::phase::{PhaseContext, ScanPhase};
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_reporting_phase_name_and_order() {
        let phase = ReportingPhase;
        assert_eq!(phase.name(), "Reporting");
        assert_eq!(phase.order(), 11);
    }

    #[tokio::test]
    async fn test_reporting_phase_with_no_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.output.dir = temp_dir.path().to_string_lossy().to_string();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = ReportingPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_reporting_phase_with_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.output.dir = temp_dir.path().to_string_lossy().to_string();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding =
            create_test_finding("Report test vulnerability", "test.rs", 42, Severity::High);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = ReportingPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);

        let json_path = temp_dir.path().join("findings.json");
        let html_path = temp_dir.path().join("report.html");
        let sarif_path = temp_dir.path().join("report.sarif");

        assert!(json_path.exists(), "JSON report should be created");
        assert!(html_path.exists(), "HTML report should be created");
        assert!(sarif_path.exists(), "SARIF report should be created");
    }

    #[tokio::test]
    async fn test_reporting_phase_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.output.dir = temp_dir.path().to_string_lossy().to_string();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let findings = vec![
            create_test_finding("Critical finding", "critical.rs", 1, Severity::Critical),
            create_test_finding("High finding", "high.rs", 10, Severity::High),
            create_test_finding("Medium finding", "medium.rs", 20, Severity::Medium),
            create_test_finding("Low finding", "low.rs", 30, Severity::Low),
        ];

        scanner.state.send_modify(|s| {
            s.findings = findings;
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = ReportingPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        let processed_findings = result.unwrap();
        assert_eq!(processed_findings.len(), 4);

        assert!(temp_dir.path().join("findings.json").exists());
        assert!(temp_dir.path().join("report.html").exists());
        assert!(temp_dir.path().join("report.sarif").exists());
    }

    #[tokio::test]
    async fn test_reporting_phase_is_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = ReportingPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_reporting_phase_creates_output_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nested_dir = temp_dir.path().join("nested").join("reports");
        let mut config = ScannerConfig::default();
        config.output.dir = nested_dir.to_string_lossy().to_string();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("Nested dir test", "test.rs", 1, Severity::Medium);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = ReportingPhase;
        let result = phase.execute(&mut ctx).await;

        assert!(result.is_ok());
        assert!(
            nested_dir.exists(),
            "Nested output directory should be created"
        );
        assert!(nested_dir.join("findings.json").exists());
    }

    #[tokio::test]
    async fn test_reporting_phase_json_content() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.output.dir = temp_dir.path().to_string_lossy().to_string();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("JSON content test", "json_test.rs", 100, Severity::High);

        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = ReportingPhase;
        let _ = phase.execute(&mut ctx).await;

        let json_path = temp_dir.path().join("findings.json");
        let json_content = std::fs::read_to_string(json_path).expect("Failed to read JSON");

        assert!(json_content.contains("JSON content test"));
        assert!(json_content.contains("json_test.rs"));
    }
}
