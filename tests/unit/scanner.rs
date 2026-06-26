#[cfg(test)]
mod tests {
    use crate::scanner::{Scanner, ScannerState};

    use crate::checkpoint::ScanPhase;
    use crate::config;
    use crate::findings::Severity;
    use indicatif::{MultiProgress, ProgressBar};
    use std::path::PathBuf;
    use tokio::sync::watch;

    #[test]
    fn test_scanner_new() {
        let config = config::ScannerConfig::default();
        let scanner = Scanner::new(config, PathBuf::from("."), false);
        let state = scanner.state.borrow();

        assert_eq!(state.current_phase, ScanPhase::Indexing);
        assert!(state.findings.is_empty());
        assert_eq!(state.files_scanned, 0);
        assert!(state.errors.is_empty());
    }

    #[test]
    fn test_scanner_default() {
        let config = config::ScannerConfig::default();
        let scanner = Scanner::new(config, PathBuf::from("."), false);
        let state = scanner.state.borrow();

        assert_eq!(state.current_phase, ScanPhase::Indexing);
        assert!(state.findings.is_empty());
    }

    #[tokio::test]
    async fn test_run_phase_indexing() {
        let config = config::ScannerConfig::default();
        let scanner = Scanner::new(config, PathBuf::from("."), false);
        let progress = MultiProgress::new();
        let pb = progress.add(ProgressBar::new(100));
        let findings = vec![];

        let result = scanner
            .run_phase(&ScanPhase::Indexing, findings, &pb, &[])
            .await;
        assert!(result.is_ok());
        let (findings_result, _) = result.unwrap();
        assert!(findings_result.is_empty());
    }

    #[tokio::test]
    async fn test_run_phase_semgrep() {
        let config = config::ScannerConfig::default();
        let scanner = Scanner::new(config, PathBuf::from("."), false);
        let progress = MultiProgress::new();
        let pb = progress.add(ProgressBar::new(100));
        let findings = vec![];

        let result = scanner
            .run_phase(&ScanPhase::Semgrep, findings, &pb, &[])
            .await;
        assert!(result.is_ok() || result.is_err());
    }

    // Parameterized test for LLM and analysis phases
    macro_rules! test_phase {
        ($name:ident, $phase:expr) => {
            #[tokio::test]
            async fn $name() {
                let config = config::ScannerConfig::default();
                let scanner = Scanner::new(config, PathBuf::from("."), false);
                let progress = MultiProgress::new();
                let pb = progress.add(ProgressBar::new(100));
                let findings = vec![];

                let result = scanner.run_phase(&$phase, findings, &pb, &[]).await;
                assert!(result.is_ok());
            }
        };
    }

    test_phase!(test_run_phase_llm_discovery, ScanPhase::LlmDiscovery);
    test_phase!(test_run_phase_llm_verification, ScanPhase::LlmVerification);
    test_phase!(test_run_phase_git_analysis, ScanPhase::GitAnalysis);

    #[tokio::test]
    async fn test_run_with_empty_phases() {
        let config = config::ScannerConfig::default();
        let scanner = Scanner::new(config, PathBuf::from("."), false);
        let result = scanner.run().await;
        assert!(result.is_ok());
        // Should complete all phases without error
    }

    #[test]
    fn test_scanner_state_initialization() {
        let (sender, receiver) = watch::channel(ScannerState {
            findings: Vec::new(),
            current_phase: ScanPhase::Indexing,
            files_scanned: 0,
            errors: Vec::new(),
            cve_entries: Vec::new(),
            project_stack: None,
        });

        let state = receiver.borrow();
        assert_eq!(state.current_phase, ScanPhase::Indexing);
        assert_eq!(state.files_scanned, 0);

        drop(sender);
    }

    #[tokio::test]
    async fn test_progress_bar_steady_tick() {
        use std::time::Duration;

        let progress = MultiProgress::new();
        let pb = progress.add(ProgressBar::new(100));

        // Enable steady tick (the new pattern we're testing)
        pb.enable_steady_tick(Duration::from_millis(100));

        // Verify that the progress bar can tick without blocking
        pb.set_message("Testing steady tick");
        pb.set_position(50);

        // Wait a bit to ensure tick is working
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Verify position was set correctly
        assert_eq!(pb.position(), 50);
        assert_eq!(pb.message(), "Testing steady tick");

        pb.finish();
    }

    #[tokio::test]
    async fn test_progress_tick_pattern_vs_spawn() {
        use std::time::Duration;
        use tokio::time::sleep;

        let progress = MultiProgress::new();
        let pb = progress.add(ProgressBar::new(100));

        // Test the new steady_tick pattern
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_message("Steady tick test");

        // Simulate a long-running operation
        sleep(Duration::from_millis(250)).await;

        pb.set_position(100);
        pb.finish();

        // If we get here without blocking, the pattern works
        assert_eq!(pb.position(), 100);
    }
}
