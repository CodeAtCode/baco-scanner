#[cfg(test)]
mod php {
    use baco::llm::LlmClient;
    use baco::llm::LlmConfig;
    use baco::llm_analysis::LlmAnalyzer;
    use std::path::Path;

    fn create_mock_analyzer(languages: Vec<String>) -> LlmAnalyzer {
        let llm_config = LlmConfig {
            base_url: "http://test".to_string(),
            api_key: "test".to_string(),
            model: "test".to_string(),
            models: vec![],
            timeout: 30,
            max_retries: 1,
            retry_backoff_ms: 1000,
            temperature: 0.5,
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            max_concurrent: 4,
        };
        let client = LlmClient::new(llm_config);
        LlmAnalyzer::new(
            client,
            languages,
            1024,
            &baco::config::ScannerConfig::default(),
        )
    }

    // ============================================================================
    // Extension Map Tests
    // ============================================================================

    #[test]
    fn test_php_files_recognized_by_extension() {
        let analyzer = create_mock_analyzer(vec!["php".to_string()]);

        assert!(analyzer.should_analyze(Path::new("test.php")));
        assert!(analyzer.should_analyze(Path::new("test.phtml")));
        assert!(analyzer.should_analyze(Path::new("/path/to/file.php")));
        assert!(analyzer.should_analyze(Path::new("includes/module.phtml")));
    }

    #[test]
    fn test_php_excluded_when_languages_rust() {
        let analyzer = create_mock_analyzer(vec!["rust".to_string()]);

        assert!(!analyzer.should_analyze(Path::new("test.php")));
        assert!(!analyzer.should_analyze(Path::new("test.phtml")));
        assert!(!analyzer.should_analyze(Path::new("includes/module.php")));

        // Verify rust files still work
        assert!(analyzer.should_analyze(Path::new("test.rs")));
    }

    #[test]
    fn test_php_with_multiple_languages() {
        let analyzer = create_mock_analyzer(vec![
            "rust".to_string(),
            "php".to_string(),
            "python".to_string(),
        ]);

        assert!(analyzer.should_analyze(Path::new("test.php")));
        assert!(analyzer.should_analyze(Path::new("test.phtml")));
        assert!(analyzer.should_analyze(Path::new("test.rs")));
        assert!(analyzer.should_analyze(Path::new("test.py")));
        assert!(!analyzer.should_analyze(Path::new("test.js")));
    }

    // ============================================================================
    // Tree-sitter Chunking Tests
    // ============================================================================

    #[test]
    fn test_php_content_parses_via_chunker() {
        let analyzer = create_mock_analyzer(vec!["php".to_string()]);
        let php_code = r#"<?php
function hello_world() {
    echo "Hello, World!";
}

class User {
    private $name;
    
    public function __construct($name) {
        $this->name = $name;
    }
    
    public function getName() {
        return $this->name;
    }
}
?>"#;

        let chunks = analyzer.chunk_code_tree_sitter(php_code, "php", 8000);

        // Should produce at least 1 chunk
        assert!(!chunks.is_empty());

        // First chunk should contain the function or class
        let first_chunk = &chunks[0];
        assert!(
            first_chunk.contains("function") || first_chunk.contains("class"),
            "Chunk should contain function or class definition"
        );

        // Should contain actual PHP code
        assert!(first_chunk.contains("<?php"));
    }

    #[test]
    fn test_php_chunker_fallback_gracefully() {
        let analyzer = create_mock_analyzer(vec!["php".to_string()]);
        // Invalid PHP that might fail parsing
        let invalid_php = "<?php this is not valid php syntax {{{";

        let chunks = analyzer.chunk_code_tree_sitter(invalid_php, "php", 8000);

        // Should fallback to truncate_code and return at least 1 chunk
        assert!(!chunks.is_empty());
        assert!(chunks[0].contains("<?php"));
    }

    // ============================================================================
    // Prompt File Tests
    // ============================================================================

    #[test]
    fn test_prompt_file_contains_php_section() {
        let prompt_content = include_str!("../../prompts/phases/llm_static_analysis.md");

        // Check for PHP section header
        assert!(
            prompt_content.contains("### PHP (Web Application Security)"),
            "Prompt file should contain PHP section header"
        );

        // Check for dangerous PHP patterns
        assert!(
            prompt_content.contains("eval()"),
            "PHP section should mention eval() dangerous function"
        );
        assert!(
            prompt_content.contains("shell_exec()") || prompt_content.contains("system()"),
            "PHP section should mention shell execution functions"
        );

        // Check for CWE references
        assert!(
            prompt_content.contains("CWE-78") || prompt_content.contains("CWE-89"),
            "PHP section should reference CWE IDs"
        );

        // Check for specific PHP vulnerabilities
        assert!(
            prompt_content.contains("SQL Injection") || prompt_content.contains("SQLi"),
            "PHP section should mention SQL injection"
        );
        assert!(
            prompt_content.contains("XSS") || prompt_content.contains("Cross-Site"),
            "PHP section should mention XSS"
        );
    }

    // ============================================================================
    // Case Insensitivity Tests
    // ============================================================================

    #[test]
    fn test_php_extension_case_insensitive() {
        let analyzer = create_mock_analyzer(vec!["php".to_string()]);

        assert!(analyzer.should_analyze(Path::new("test.PHP")));
        assert!(analyzer.should_analyze(Path::new("test.Php")));
        assert!(analyzer.should_analyze(Path::new("test.PHTML")));
    }
}
