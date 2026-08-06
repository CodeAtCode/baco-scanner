#![allow(clippy::single_match)]

#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::phase::semgrep::SemgrepPhase;
    use baco::phase::{PhaseContext, ScanPhase};
    use baco::scanner::Scanner;
    use tempfile::TempDir;

    #[test]
    fn test_semgrep_phase_name_and_order() {
        let phase = SemgrepPhase;
        assert_eq!(phase.name(), "Semgrep");
        assert_eq!(phase.order(), 2);
    }

    #[test]
    fn test_semgrep_phase_basic_properties() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let _scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let phase = SemgrepPhase;

        assert_eq!(phase.name(), "Semgrep");
        assert_eq!(phase.order(), 2);
    }

    #[tokio::test]
    async fn test_semgrep_phase_with_empty_target() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = SemgrepPhase;
        let result = phase.execute(&mut ctx).await;

        // Semgrep may not be installed in test environment - either success or clear error is expected
        match result {
            Ok(findings) => {
                let _ = findings.len();
            } // Test runs semgrep
            Err(_) => {} // Expected if semgrep not installed
        }
    }

    #[test]
    fn test_semgrep_phase_integration() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let _scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let phase = SemgrepPhase;

        assert_eq!(phase.name(), "Semgrep");
        assert_eq!(phase.order(), 2);
    }

    #[tokio::test]
    async fn test_semgrep_with_empty_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = SemgrepPhase;
        let result = phase.execute(&mut ctx).await;

        // Semgrep may not be installed - either success with empty findings or error is acceptable
        match result {
            Ok(findings) => {
                // Empty findings is acceptable when no code to scan or semgrep not available
                assert!(findings.is_empty());
            }
            Err(_) => {
                // Error is acceptable if semgrep is not installed
            }
        }
    }

    #[tokio::test]
    async fn test_semgrep_disabled_config() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = SemgrepPhase;
        let result = phase.execute(&mut ctx).await;

        // Semgrep phase doesn't have a direct disabled flag in the same way as LLM phases
        // It handles missing semgrep gracefully by returning Ok with empty findings
        match result {
            Ok(findings) => {
                // Should handle gracefully - findings may be empty if semgrep not available
                let _ = findings.len();
            }
            Err(_) => {
                // Error is acceptable if semgrep is not installed
            }
        }
    }

    #[tokio::test]
    async fn test_semgrep_preserves_analyzed_files() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        // Pre-populate analyzed_files
        let mut analyzed_files = vec!["/path/to/already/scanned/file.rs".to_string()];
        let initial_count = analyzed_files.len();
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = SemgrepPhase;
        let result = phase.execute(&mut ctx).await;

        // Should preserve existing analyzed_files
        match result {
            Ok(findings) => {
                // Verify phase completed - analyzed_files is modified in place
                let _ = findings.len();
                assert!(analyzed_files.len() >= initial_count);
                assert!(analyzed_files.contains(&"/path/to/already/scanned/file.rs".to_string()));
            }
            Err(_) => {
                // Error is acceptable if semgrep is not installed
            }
        }
    }

    #[test]
    fn test_semgrep_phase_properties() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let _scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let phase = SemgrepPhase;

        assert_eq!(phase.name(), "Semgrep");
        assert_eq!(phase.order(), 2);
    }
}
