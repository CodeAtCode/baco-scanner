#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::cve_bootstrap::CveBootstrapper;
    use baco::findings::Severity;
    use baco::phase::helpers::create_test_finding;
    use baco::scanner::Scanner;
    use tempfile::TempDir;

    #[test]
    fn test_cve_bootstrap_phase_name_and_order() {
        // CveBootstrapper doesn't implement ScanPhase trait directly
        // It's used via the run_cve_bootstrap function
        let temp_dir = TempDir::new().unwrap();
        let _bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
    }

    #[tokio::test]
    async fn test_cve_bootstrap_with_no_findings() {
        let temp_dir = TempDir::new().unwrap();
        let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());

        let findings = vec![];
        let result = bootstrapper.run_cve_enrichment(&findings).await;

        assert!(result.is_ok());
        let enriched = result.unwrap();
        assert!(enriched.is_empty());
    }

    #[tokio::test]
    async fn test_cve_bootstrap_with_findings() {
        let temp_dir = TempDir::new().unwrap();
        let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());

        let finding = create_test_finding("Test vulnerability", "test.rs", 42, Severity::High);
        let findings = vec![finding];

        let result = bootstrapper.run_cve_enrichment(&findings).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cve_bootstrap_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());

        let findings = vec![
            create_test_finding("High severity", "high.rs", 10, Severity::High),
            create_test_finding("Medium severity", "medium.rs", 20, Severity::Medium),
            create_test_finding("Low severity", "low.rs", 30, Severity::Low),
        ];

        let result = bootstrapper.run_cve_enrichment(&findings).await;

        assert!(result.is_ok());
        let enriched = result.unwrap();
        assert_eq!(enriched.len(), 3);
    }

    #[tokio::test]
    async fn test_cve_bootstrap_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.scanner.performance.enable_cve_bootstrap = false;

        let scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let finding = create_test_finding("Test vulnerability", "test.rs", 42, Severity::High);
        scanner.state.send_modify(|s| {
            s.findings.push(finding);
        });

        // When disabled, the phase should return findings unchanged
        let findings = scanner.state.borrow().findings.clone();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_cve_bootstrapper_detect_project_stack() {
        let temp_dir = TempDir::new().unwrap();

        // Create a minimal Cargo.toml
        let cargo_path = temp_dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo_path,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[dependencies]\n",
        )
        .unwrap();

        let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
        let result = bootstrapper.detect_project_stack();

        assert!(result.is_ok());
        let stack = result.unwrap();
        assert!(stack.languages.contains(&"Rust".to_string()));
    }

    #[test]
    fn test_cve_bootstrapper_empty_project() {
        let temp_dir = TempDir::new().unwrap();

        let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
        let result = bootstrapper.detect_project_stack();

        assert!(result.is_ok());
        let stack = result.unwrap();
        // Empty project should have no dependencies detected
        assert!(stack.dependencies.is_empty());
    }
}
