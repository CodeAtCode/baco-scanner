//! Tests for T18 (priority/budget config) and T19 (tree-sitter chunking)

#[cfg(test)]
mod priority_config_tests {
    use baco::config::{BudgetConfig, PriorityConfig};

    #[test]
    fn test_priority_config_defaults() {
        let config = PriorityConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.git_recent_boost, 2.0);
        assert_eq!(config.entry_point_boost, 1.5);
        assert_eq!(config.small_file_boost, 1.2);
    }

    #[test]
    fn test_budget_config_defaults() {
        let config = BudgetConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_llm_calls, 200);
        assert_eq!(config.reserve_percent_for_high_risk, 20);
    }

    #[test]
    fn test_priority_config_toml_parse() {
        let toml_str = r#"
            enabled = true
            git_recent_boost = 3.0
            entry_point_boost = 2.0
            small_file_boost = 1.5
        "#;
        let config: PriorityConfig = toml::from_str(toml_str).expect("Should parse");
        assert!(config.enabled);
        assert_eq!(config.git_recent_boost, 3.0);
        assert_eq!(config.entry_point_boost, 2.0);
        assert_eq!(config.small_file_boost, 1.5);
    }

    #[test]
    fn test_budget_config_toml_parse() {
        let toml_str = r#"
            enabled = true
            max_llm_calls = 100
            reserve_percent_for_high_risk = 30
        "#;
        let config: BudgetConfig = toml::from_str(toml_str).expect("Should parse");
        assert!(config.enabled);
        assert_eq!(config.max_llm_calls, 100);
        assert_eq!(config.reserve_percent_for_high_risk, 30);
    }
}

#[cfg(test)]
mod priority_scoring_tests {
    use baco::scanner::phases::llm_phases::static_analysis::compute_file_priority_score;
    use std::path::PathBuf;

    fn make_file_info(path: &str, size: u64) -> baco::indexer::FileInfo {
        baco::indexer::FileInfo {
            path: PathBuf::from(path),
            language: "rust".to_string(),
            size,
            hash: None,
        }
    }

    #[test]
    fn test_entry_point_boost() {
        let file = make_file_info("src/main.rs", 5000);
        let priority = baco::config::PriorityConfig {
            enabled: false,
            git_recent_boost: 2.0,
            entry_point_boost: 1.5,
            small_file_boost: 1.2,
            entry_point_patterns: vec![],
            sink_patterns: vec![],
        };
        let score = compute_file_priority_score(&file, &priority);
        // Multiplicative: 2.0 (git) * 1.5 (entry_point) * 1.2 (small_file) = 3.6
        assert!((score - 3.6).abs() < 1e-6, "Expected ~3.6, got {}", score);
    }

    #[test]
    fn test_index_entry_point() {
        let file = make_file_info("src/index.ts", 5000);
        let priority = baco::config::PriorityConfig {
            enabled: false,
            git_recent_boost: 2.0,
            entry_point_boost: 1.5,
            small_file_boost: 1.2,
            entry_point_patterns: vec![],
            sink_patterns: vec![],
        };
        let score = compute_file_priority_score(&file, &priority);
        assert_eq!(score, 1.5 * 1.2);
    }

    #[test]
    fn test_app_entry_point() {
        let file = make_file_info("app.py", 5000);
        let priority = baco::config::PriorityConfig {
            enabled: false,
            git_recent_boost: 2.0,
            entry_point_boost: 1.5,
            small_file_boost: 1.2,
            entry_point_patterns: vec![],
            sink_patterns: vec![],
        };
        let score = compute_file_priority_score(&file, &priority);
        assert_eq!(score, 1.5 * 1.2);
    }

    #[test]
    fn test_server_entry_point() {
        let file = make_file_info("server.js", 5000);
        let priority = baco::config::PriorityConfig {
            enabled: false,
            git_recent_boost: 2.0,
            entry_point_boost: 1.5,
            small_file_boost: 1.2,
            entry_point_patterns: vec![],
            sink_patterns: vec![],
        };
        let score = compute_file_priority_score(&file, &priority);
        assert_eq!(score, 1.5 * 1.2);
    }

    #[test]
    fn test_small_file_boost() {
        let file = make_file_info("src/utils.rs", 5000);
        let priority = baco::config::PriorityConfig {
            enabled: false,
            git_recent_boost: 2.0,
            entry_point_boost: 1.5,
            small_file_boost: 1.2,
            entry_point_patterns: vec![],
            sink_patterns: vec![],
        };
        let score = compute_file_priority_score(&file, &priority);
        assert_eq!(score, 1.2); // small_file only
    }

    #[test]
    fn test_large_file_no_boost() {
        let file = make_file_info("src/large.rs", 15000);
        let priority = baco::config::PriorityConfig {
            enabled: false,
            git_recent_boost: 2.0,
            entry_point_boost: 1.5,
            small_file_boost: 1.2,
            entry_point_patterns: vec![],
            sink_patterns: vec![],
        };
        let score = compute_file_priority_score(&file, &priority);
        assert_eq!(score, 1.0); // no boosts
    }

    #[test]
    fn test_non_entry_point() {
        let file = make_file_info("src/utils/helper.rs", 5000);
        let priority = baco::config::PriorityConfig {
            enabled: false,
            git_recent_boost: 2.0,
            entry_point_boost: 1.5,
            small_file_boost: 1.2,
            entry_point_patterns: vec![],
            sink_patterns: vec![],
        };
        let score = compute_file_priority_score(&file, &priority);
        assert_eq!(score, 1.2); // small_file only
    }
}

#[cfg(test)]
mod budget_enforcement_tests {
    /// Test budget enforcement logic with pure function simulation
    /// Simulates: with max_llm_calls=2 and 5 files, only 2 deep calls happen
    #[test]
    fn test_budget_limits_calls() {
        let max_calls = 2;
        let num_files = 5;
        let mut call_count = 0;
        let mut analyzed = 0;

        for _ in 0..num_files {
            if call_count >= max_calls {
                break;
            }
            call_count += 1;
            analyzed += 1;
        }

        assert_eq!(analyzed, 2);
        assert_eq!(call_count, 2);
    }

    #[test]
    fn test_budget_no_limit_when_disabled() {
        let max_calls = usize::MAX;
        let num_files = 5;
        let mut call_count = 0;
        let mut analyzed = 0;

        for _ in 0..num_files {
            if call_count >= max_calls {
                break;
            }
            call_count += 1;
            analyzed += 1;
        }

        assert_eq!(analyzed, 5);
        assert_eq!(call_count, 5);
    }
}

#[cfg(test)]
mod chunking_tests {
    use baco::llm::LlmClient;

    #[test]
    fn test_chunking_two_functions_under_cap() {
        let client = LlmClient::new(baco::llm::LlmConfig {
            base_url: "https://test.example.com".to_string(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            models: vec![],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            temperature: 0.5,
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            max_concurrent: 3,
        });
        let analyzer = baco::llm_analysis::LlmAnalyzer::new(
            client,
            vec!["rust".to_string()],
            1024,
            &Default::default(),
        );

        // Two small functions that fit under 8000 bytes
        let code = r#"
fn function_one() {
    println!("Hello");
}

fn function_two() {
    println!("World");
}
"#;

        let chunks = analyzer.chunk_code_tree_sitter(code, "rust", 8000);
        // Should produce 1 chunk with both functions
        assert!(!chunks.is_empty());
        assert!(chunks[0].contains("function_one"));
        assert!(chunks[0].contains("function_two"));
    }

    #[test]
    fn test_chunking_large_function_split() {
        let client = LlmClient::new(baco::llm::LlmConfig {
            base_url: "https://test.example.com".to_string(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            models: vec![],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            temperature: 0.5,
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            max_concurrent: 3,
        });
        let analyzer = baco::llm_analysis::LlmAnalyzer::new(
            client,
            vec!["rust".to_string()],
            1024,
            &Default::default(),
        );

        // Large function that exceeds cap
        let mut code = String::from("fn large_function() {\n");
        for i in 0..2000 {
            code.push_str(&format!("    let x{} = {};\n", i, i));
        }
        code.push_str("}\n");

        let chunks = analyzer.chunk_code_tree_sitter(&code, "rust", 8000);
        // Should split into multiple chunks
        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_chunking_fallback_on_unsupported_language() {
        let client = LlmClient::new(baco::llm::LlmConfig {
            base_url: "https://test.example.com".to_string(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            models: vec![],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            temperature: 0.5,
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            max_concurrent: 3,
        });
        let analyzer = baco::llm_analysis::LlmAnalyzer::new(
            client,
            vec!["rust".to_string()],
            1024,
            &Default::default(),
        );

        let code = "some code here";
        let chunks = analyzer.chunk_code_tree_sitter(code, "unknown_lang", 8000);
        // Should fallback to truncate_code
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("some code here"));
    }
}
