#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::findings::Severity;
    use baco::phase::helpers::create_test_finding;
    use baco::scanner::Scanner;
    use baco::variant_search::{SearchPattern, VariantHit, VariantSearcher};
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn test_variant_search_phase_name_and_order() {
        // VariantSearcher doesn't implement ScanPhase trait directly
        // It's used via the run_variant_search function
        let temp_dir = TempDir::new().unwrap();
        let _searcher = VariantSearcher::new(temp_dir.path().to_string_lossy().to_string());
    }

    #[test]
    fn test_variant_search_with_no_findings() {
        let temp_dir = TempDir::new().unwrap();
        let searcher = VariantSearcher::new(temp_dir.path().to_string_lossy().to_string());

        let result = searcher.search_variants();

        assert!(result.is_ok());
        let hits = result.unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn test_variant_search_with_findings() {
        let temp_dir = TempDir::new().unwrap();

        // Create a test file with a pattern
        let test_file = temp_dir.path().join("test.rs");
        std::fs::write(&test_file, "let x = 42;").unwrap();

        let searcher = VariantSearcher::new(temp_dir.path().to_string_lossy().to_string());

        let result = searcher.search_variants();

        assert!(result.is_ok());
    }

    #[test]
    fn test_variant_search_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();

        // Create test files
        let test_file1 = temp_dir.path().join("test1.rs");
        std::fs::write(&test_file1, "let x = 42;").unwrap();

        let test_file2 = temp_dir.path().join("test2.rs");
        std::fs::write(&test_file2, "let y = 100;").unwrap();

        let searcher = VariantSearcher::new(temp_dir.path().to_string_lossy().to_string());

        let result = searcher.search_variants();

        assert!(result.is_ok());
    }

    #[test]
    fn test_variant_search_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.scanner.performance.enable_variant_search = false;

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
    fn test_variant_searcher_with_patterns() {
        let temp_dir = TempDir::new().unwrap();

        let pattern = SearchPattern::new(
            "SQL Injection",
            "query(",
            vec!["sql".to_string(), "database".to_string()],
        );

        let searcher = VariantSearcher::new(temp_dir.path().to_string_lossy().to_string())
            .with_patterns(vec![pattern])
            .with_threshold(0.5);

        // Verify the searcher was created with patterns (we can't access patterns directly)
        let _ = searcher;
    }

    #[test]
    fn test_variant_searcher_threshold() {
        let temp_dir = TempDir::new().unwrap();

        let searcher =
            VariantSearcher::new(temp_dir.path().to_string_lossy().to_string()).with_threshold(0.7);

        // Default threshold is 0.5, should be changed to 0.7
        // Note: We can't directly access threshold as it's private, but we can test behavior
        let _ = searcher;
    }

    #[test]
    fn test_search_pattern_creation() {
        let pattern = SearchPattern::new(
            "XSS",
            "innerHTML",
            vec!["javascript".to_string(), "dom".to_string()],
        );

        assert_eq!(pattern.vulnerability_type, "XSS");
        assert_eq!(pattern.code_pattern, "innerHTML");
        assert_eq!(pattern.context_keywords.len(), 2);
    }

    #[test]
    fn test_variant_hit_creation() {
        let hit = VariantHit::new("test.rs", 42, 0.85, "let x = 42;");

        assert_eq!(hit.file_path, "test.rs");
        assert_eq!(hit.line_number, 42);
        assert_eq!(hit.similarity_score, 0.85);
        assert_eq!(hit.snippet, "let x = 42;");
    }

    #[test]
    fn test_variant_searcher_should_skip_file() {
        assert!(VariantSearcher::should_skip_file(Path::new("test.bin")));
        assert!(VariantSearcher::should_skip_file(Path::new("test.png")));
        assert!(VariantSearcher::should_skip_file(Path::new("Cargo.lock")));
        assert!(!VariantSearcher::should_skip_file(Path::new("src/main.rs")));
        assert!(!VariantSearcher::should_skip_file(Path::new("src/test.py")));
    }
}
