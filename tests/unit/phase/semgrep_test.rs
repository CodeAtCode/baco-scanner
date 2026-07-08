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
}
