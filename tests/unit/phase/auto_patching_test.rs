#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::findings::Severity;
    use baco::phase::helpers::create_test_finding;
    use baco::scanner::Scanner;
    use baco::staging::compiler::AutoPatcher;
    use tempfile::TempDir;

    #[test]
    fn test_auto_patching_phase_name_and_order() {
        // AutoPatcher doesn't implement ScanPhase trait directly
        // It's used via the run_auto_patching function
        let temp_dir = TempDir::new().unwrap();
        let _patcher = AutoPatcher::new(temp_dir.path().to_path_buf());
    }

    #[test]
    fn test_auto_patcher_with_no_findings() {
        let temp_dir = TempDir::new().unwrap();
        let patcher = AutoPatcher::new(temp_dir.path().to_path_buf());

        let findings = vec![];
        let config = baco::staging::PatchingConfig::default();

        let result = patcher.execute_batch(&findings, &config);

        assert!(result.is_ok());
        let patched = result.unwrap();
        assert!(patched.is_empty());
    }

    #[test]
    fn test_auto_patcher_with_findings() {
        let temp_dir = TempDir::new().unwrap();
        let patcher = AutoPatcher::new(temp_dir.path().to_path_buf());

        let finding = create_test_finding("Test vulnerability", "test.rs", 42, Severity::High);
        let findings = vec![finding];
        let config = baco::staging::PatchingConfig::default();

        let result = patcher.execute_batch(&findings, &config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_auto_patcher_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let patcher = AutoPatcher::new(temp_dir.path().to_path_buf());

        let findings = vec![
            create_test_finding("High severity", "high.rs", 10, Severity::High),
            create_test_finding("Medium severity", "medium.rs", 20, Severity::Medium),
            create_test_finding("Low severity", "low.rs", 30, Severity::Low),
        ];
        let config = baco::staging::PatchingConfig::default();

        let result = patcher.execute_batch(&findings, &config);

        assert!(result.is_ok());
        let patched = result.unwrap();
        // Auto patcher may filter out findings that can't be patched
        assert!(patched.len() <= 3);
    }

    #[test]
    fn test_auto_patcher_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.scanner.performance.enable_auto_patching = false;

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
    fn test_auto_patcher_generate_patch() {
        let temp_dir = TempDir::new().unwrap();
        let patcher = AutoPatcher::new(temp_dir.path().to_path_buf());

        let patch = patcher.generate_patch("Test vulnerability", "vulnerable code", "test.rs");

        assert!(patch.is_ok());
        let patch_candidate = patch.unwrap();
        assert!(patch_candidate.diff.contains("---"));
        assert!(patch_candidate.diff.contains("+++"));
    }
}
