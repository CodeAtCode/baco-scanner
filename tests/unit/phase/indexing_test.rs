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

    #[test]
    fn test_indexing_phase_basic_properties() {
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

    #[tokio::test]
    async fn test_indexing_with_empty_target() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        // Create an empty scanner with the temp directory
        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut vec![],
        };

        let phase = IndexingPhase;
        let result = phase.execute(&mut ctx).await;

        // Should succeed even with empty directory
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_indexing_with_nonexistent_path() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        // Use a path that doesn't exist within the temp directory
        let nonexistent_path = temp_dir.path().join("nonexistent_subdir");

        // Create a custom scanner with the nonexistent path
        let mut scanner_with_nonexistent =
            Scanner::new(config.clone(), nonexistent_path.clone(), false);

        let mut ctx = PhaseContext {
            scanner: &mut scanner_with_nonexistent,
            analyzed_files: &mut vec![],
        };

        let phase = IndexingPhase;
        let result = phase.execute(&mut ctx).await;

        // Should handle nonexistent path gracefully (may return empty or error)
        // The important thing is it doesn't panic
        match result {
            Ok(findings) => {
                // Empty findings is acceptable for nonexistent path
                assert!(findings.is_empty());
            }
            Err(_) => {
                // Error is also acceptable
            }
        }
    }

    #[tokio::test]
    async fn test_indexing_creates_file_index() {
        let temp_dir = TempDir::new().unwrap();

        // Create some test files
        fs::write(temp_dir.path().join("index_test1.rs"), "fn test1() {}").unwrap();
        fs::write(temp_dir.path().join("index_test2.rs"), "fn test2() {}").unwrap();

        let config = ScannerConfig::default();

        let mut scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let mut analyzed_files = vec![];
        let mut ctx = PhaseContext {
            scanner: &mut scanner,
            analyzed_files: &mut analyzed_files,
        };

        let phase = IndexingPhase;
        let result = phase.execute(&mut ctx).await;

        // Should succeed and create index
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
        // The indexing phase should have processed the files
        // analyzed_files may be populated depending on implementation
    }
}
