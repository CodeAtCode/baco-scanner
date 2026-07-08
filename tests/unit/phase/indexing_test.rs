#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::phase::indexing::IndexingPhase;
    use baco::phase::{PhaseContext, ScanPhase};
    use baco::scanner::Scanner;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_indexing_phase_name_and_order() {
        let phase = IndexingPhase;
        assert_eq!(phase.name(), "Indexing");
        assert_eq!(phase.order(), 1);
    }

    #[tokio::test]
    async fn test_indexing_phase_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = IndexingPhase;
        let result = phase.execute(&mut ctx).await;

        // Should succeed with empty index
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_indexing_phase_with_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create some test files
        fs::write(temp_dir.path().join("test1.rs"), "fn main() {}").unwrap();
        fs::write(temp_dir.path().join("test2.py"), "print('hello')").unwrap();

        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = IndexingPhase;
        let result = phase.execute(&mut ctx).await;

        // Should succeed and index the files
        assert!(result.is_ok());
    }
}
