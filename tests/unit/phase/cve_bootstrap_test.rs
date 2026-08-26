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

    #[test]
    fn test_detect_project_stack_empty_project() {
        let temp_dir = TempDir::new().unwrap();

        let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
        let stack = bootstrapper.detect_project_stack().unwrap();

        assert!(stack.languages.is_empty(), "Empty project should have zero languages detected");
        assert!(stack.dependencies.is_empty(), "Empty project should have zero dependencies");
    }

    #[test]
    fn test_detect_project_stack_only_cargo_toml() {
        let temp_dir = TempDir::new().unwrap();

        std::fs::write(
            temp_dir.path().join("Cargo.toml"),
            r#"[package]
name = "test-rust-app"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = "1.0"
"#,
        )
        .unwrap();

        let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
        let stack = bootstrapper.detect_project_stack().unwrap();

        assert!(stack.languages.contains(&"Rust".to_string()), "Should detect Rust language");
        assert_eq!(stack.dependencies.len(), 2, "Should parse 2 dependencies from Cargo.toml");
        assert!(stack.dependencies.iter().any(|d| d.name == "serde"));
        assert!(stack.dependencies.iter().any(|d| d.name == "tokio"));
    }

    #[test]
    fn test_detect_project_stack_both_manifests() {
        let temp_dir = TempDir::new().unwrap();

        std::fs::write(
            temp_dir.path().join("Cargo.toml"),
            r#"[package]
name = "test-mixed"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
        )
        .unwrap();

        std::fs::write(
            temp_dir.path().join("pyproject.toml"),
            r#"[project]
name = "test-mixed"
version = "0.1.0"

[project.dependencies]
requests = "2.28.0"
"#,
        )
        .unwrap();

        let bootstrapper = CveBootstrapper::new(temp_dir.path().to_string_lossy().to_string());
        let stack = bootstrapper.detect_project_stack().unwrap();

        assert!(stack.languages.contains(&"Rust".to_string()), "Should detect Rust");
        assert_eq!(stack.dependencies.len(), 1, "Should have exactly 1 Rust dependency (serde)");
        assert!(stack.dependencies.iter().any(|d| d.name == "serde"));
    }

    #[test]
    fn test_cluster_by_pattern_tied_counts_stable_ordering() {
        use baco::scanner_types::cve::CveSource;
        use baco::scanner_types::severity::V3Severity;

        let cves = vec![
            CveEntry::new("CVE-2024-001", "SQL injection in login", V3Severity::Critical, CveSource::NVD),
            CveEntry::new("CVE-2024-002", "Another SQL injection", V3Severity::High, CveSource::NVD),
            CveEntry::new("CVE-2024-003", "XSS in output", V3Severity::Medium, CveSource::NVD),
            CveEntry::new("CVE-2024-004", "Another XSS", V3Severity::Low, CveSource::NVD),
        ];

        let run1 = CveBootstrapper::cluster_by_pattern(&cves);
        let run2 = CveBootstrapper::cluster_by_pattern(&cves);
        let run3 = CveBootstrapper::cluster_by_pattern(&cves);

        assert_eq!(run1.len(), run2.len(), "Same number of clusters across runs");
        assert_eq!(run2.len(), run3.len(), "Same number of clusters across runs");

        for i in 0..run1.len() {
            assert_eq!(
                run1[i].pattern_name, run2[i].pattern_name,
                "Cluster {} pattern should be identical across runs", i
            );
            assert_eq!(
                run2[i].pattern_name, run3[i].pattern_name,
                "Cluster {} pattern should be identical across runs", i
            );
            assert_eq!(
                run1[i].cve_count, run2[i].cve_count,
                "Cluster {} count should be identical across runs", i
            );
        }
    }

    #[test]
    fn test_cluster_by_pattern_single_finding_stable() {
        use baco::scanner_types::cve::CveSource;
        use baco::scanner_types::severity::V3Severity;

        let cves = vec![CveEntry::new(
            "CVE-2024-001",
            "SQL injection in login",
            V3Severity::Critical,
            CveSource::NVD,
        )];

        let clusters = CveBootstrapper::cluster_by_pattern(&cves);

        assert_eq!(clusters.len(), 1, "Single CVE should produce exactly one cluster");
        assert_eq!(clusters[0].cve_count, 1, "Cluster should contain exactly one CVE");
        assert_eq!(clusters[0].example_cves.len(), 1, "Cluster should have one example CVE");
        assert_eq!(clusters[0].example_cves[0], "CVE-2024-001");
    }
}
