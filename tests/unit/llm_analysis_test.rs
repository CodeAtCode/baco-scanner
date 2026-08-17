#[cfg(test)]
mod tests {
    use baco::llm::LlmClient;
    use baco::llm::LlmConfig;
    use baco::llm_analysis::{
        extract_cwe_id, format_cwe_specs, generate_recommendation, LlmAnalyzer,
    };
    use baco::llm_metrics::LlmMetricsTracker;
    use baco::retrieval::CweDocument;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_parse_llm_response_with_description() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        let json_response = r#"[
            {
                "severity": "critical",
                "title": "Buffer overflow test",
                "description": "This is a test vulnerability description with 50+ characters",
                "line": 10,
                "cwe_id": "CWE-120",
                "exploit_scenario": "Test exploit",
                "attack_complexity": "low",
                "impact": "RCE",
                "fix_code": "Fixed code",
                "diff_hunk": "@@ -10,5 +10,7 @@",
                "recommendation": "Use strncpy"
            }
        ]"#;

        let result: Result<_, String> =
            analyzer.parse_llm_response(json_response, "test.c", "test-model");

        assert!(result.is_ok(), "Parsing should succeed");
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1, "Should find 1 vulnerability");
        assert_eq!(findings[0].title, "Buffer overflow test");
        assert!(
            findings[0].description.len() > 50,
            "Description should be preserved"
        );
    }

    #[tokio::test]
    async fn test_parse_llm_response_with_empty_description() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        let json_response = r#"[
            {
                "severity": "medium",
                "title": "Test finding",
                "description": "",
                "line": 15,
                "cwe_id": "CWE-78",
                "exploit_scenario": "Test",
                "attack_complexity": "medium",
                "impact": "High",
                "fix_code": "Fix",
                "diff_hunk": "@@ -15,5 +15,7 @@",
                "recommendation": "Validate input"
            }
        ]"#;

        let result: Result<_, String> =
            analyzer.parse_llm_response(json_response, "test.c", "test-model");

        assert!(result.is_ok(), "Parsing should succeed");
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1, "Should find 1 vulnerability");
        assert_eq!(
            findings[0].description.len(),
            0,
            "Empty description should be preserved"
        );
    }

    #[tokio::test]
    async fn test_parse_llm_response_with_markdown_fences() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        let json_response = r#"```json
[
    {
        "severity": "high",
        "title": "Code injection",
        "description": "Test description for code injection vulnerability",
        "line": 20,
        "cwe_id": "CWE-94",
        "exploit_scenario": "Test",
        "attack_complexity": "low",
        "impact": "RCE",
        "fix_code": "Fix",
        "diff_hunk": "@@ -20,5 +20,7 @@",
        "recommendation": "Sanitize input"
    }
]
```"#;

        let result: Result<_, String> =
            analyzer.parse_llm_response(json_response, "test.c", "test-model");

        assert!(
            result.is_ok(),
            "Parsing should succeed with markdown fences"
        );
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1, "Should find 1 vulnerability");
        assert_eq!(findings[0].title, "Code injection");
        assert_eq!(
            findings[0].description,
            "Test description for code injection vulnerability"
        );
    }

    #[tokio::test]
    async fn test_parse_llm_response_multiple_findings() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        let json_response = r#"[
            {
                "severity": "critical",
                "title": "Buffer overflow",
                "description": "Buffer overflow vulnerability",
                "line": 10
            },
            {
                "severity": "high",
                "title": "SQL injection",
                "description": "SQL injection vulnerability",
                "line": 20
            },
            {
                "severity": "medium",
                "title": "XSS",
                "description": "Cross-site scripting",
                "line": 30
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 3, "Should find 3 vulnerabilities");
    }

    #[tokio::test]
    async fn test_parse_llm_response_invalid_json() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        let json_response = "not valid json";
        let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 0, "Invalid JSON should return empty findings");
    }

    #[tokio::test]
    async fn test_parse_llm_response_missing_fields() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        // Missing line field - should be skipped
        let json_response = r#"[
            {
                "severity": "high",
                "title": "Missing line"
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 0, "Missing required fields should skip finding");
    }

    #[test]
    fn test_format_cwe_specs_empty() {
        let results: Vec<&CweDocument> = vec![];
        let formatted = format_cwe_specs(&results);
        assert_eq!(formatted, "");
    }

    #[test]
    fn test_format_cwe_specs_single() {
        let doc = CweDocument {
            cwe_id: "CWE-120".to_string(),
            name: "Buffer Copy without Checking Size".to_string(),
            description: "Classic buffer overflow".to_string(),
            examples: vec!["gets() is unsafe".to_string()],
            mitigation: "Use strncpy()".to_string(),
        };

        let formatted = format_cwe_specs(&[&doc]);
        assert!(formatted.contains("CWE-120"));
        assert!(formatted.contains("Buffer Copy without Checking Size"));
        assert!(formatted.contains("Classic buffer overflow"));
        assert!(formatted.contains("Mitigation: Use strncpy()"));
    }

    #[test]
    fn test_format_cwe_specs_multiple() {
        let doc1 = CweDocument {
            cwe_id: "CWE-120".to_string(),
            name: "Buffer Copy".to_string(),
            description: "Description 1".to_string(),
            examples: vec![],
            mitigation: "Mitigation 1".to_string(),
        };

        let doc2 = CweDocument {
            cwe_id: "CWE-78".to_string(),
            name: "OS Command Injection".to_string(),
            description: "Description 2".to_string(),
            examples: vec![],
            mitigation: "Mitigation 2".to_string(),
        };

        let formatted = format_cwe_specs(&[&doc1, &doc2]);
        assert!(formatted.contains("CWE-120"));
        assert!(formatted.contains("CWE-78"));
        assert!(formatted.contains("Description 1"));
        assert!(formatted.contains("Description 2"));
    }

    #[test]
    fn test_extract_cwe_id_found() {
        let description = "This vulnerability relates to CWE-120 buffer overflow";
        let result = extract_cwe_id(description);
        assert_eq!(result, Some("CWE-120".to_string()));
    }

    #[test]
    fn test_extract_cwe_id_not_found() {
        let description = "This is a generic vulnerability";
        let result = extract_cwe_id(description);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_cwe_id_multiple() {
        let description = "Related to CWE-120 and CWE-78";
        let result = extract_cwe_id(description);
        assert_eq!(result, Some("CWE-120".to_string())); // Should get first match
    }

    #[test]
    fn test_generate_recommendation_sql_injection() {
        let rec = generate_recommendation("SQL Injection", "User input in SQL query");
        assert!(rec.contains("parameterized"));
        assert!(rec.contains("prepared statements"));
    }

    #[test]
    fn test_generate_recommendation_command_injection() {
        let rec = generate_recommendation("Command Injection", "Shell command execution");
        assert!(rec.contains("shell command"));
        assert!(rec.contains("validate"));
    }

    #[test]
    fn test_generate_recommendation_xss() {
        let rec = generate_recommendation("XSS", "Cross-site scripting");
        assert!(rec.contains("Escape"));
        assert!(rec.contains("encoding"));
    }

    #[test]
    fn test_generate_recommendation_buffer_overflow() {
        let rec = generate_recommendation("Buffer Overflow", "Memory corruption");
        assert!(rec.contains("bounds checking"));
    }

    #[test]
    fn test_generate_recommendation_use_after_free() {
        let rec = generate_recommendation("Use After Free", "UAF vulnerability");
        assert!(rec.contains("smart pointers") || rec.contains("nullification"));
    }

    #[test]
    fn test_generate_recommendation_null_dereference() {
        let rec = generate_recommendation("Null Pointer Dereference", "NULL access");
        assert!(rec.contains("null") || rec.contains("Option"));
    }

    #[test]
    fn test_generate_recommendation_format_string() {
        let rec = generate_recommendation("Format String", "printf vulnerability");
        assert!(rec.contains("format specifiers"));
    }

    #[test]
    fn test_generate_recommendation_generic_user_input() {
        let rec = generate_recommendation("Generic", "User input not validated");
        assert!(rec.contains("Validate") || rec.contains("sanitize"));
    }

    #[test]
    fn test_generate_recommendation_generic_untrusted() {
        let rec = generate_recommendation("Generic", "Untrusted data");
        assert!(rec.contains("untrusted") || rec.contains("validation"));
    }

    #[test]
    fn test_generate_recommendation_fallback() {
        let rec = generate_recommendation("Unknown Type", "Some description");
        assert!(rec.contains("Review"));
        assert!(rec.contains("Unknown Type"));
    }

    #[tokio::test]
    async fn test_truncate_code_within_limit() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        let short_code = "int x = 42;";
        let truncated = analyzer.truncate_code(short_code);
        assert_eq!(truncated, short_code);
    }

    #[tokio::test]
    async fn test_truncate_code_exceeds_limit() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        let long_code = "x".repeat(10000);
        let truncated = analyzer.truncate_code(&long_code);

        // The truncated result contains 8000 chars of code + suffix, so len > 8000
        // But the actual code portion is exactly 8000
        assert_eq!(&truncated[..8000], "x".repeat(8000));
        assert!(truncated.contains("[truncated"));
        assert!(truncated.contains("2000 chars omitted"));
    }

    #[tokio::test]
    async fn test_should_analyze_supported_extension() {
        let languages = vec!["c".to_string(), "rust".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        );

        assert!(analyzer.should_analyze(std::path::Path::new("test.c")));
        assert!(analyzer.should_analyze(std::path::Path::new("test.rs")));
        assert!(!analyzer.should_analyze(std::path::Path::new("test.py")));
    }

    #[tokio::test]
    async fn test_analyze_file_too_large() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1, // 1KB max
            &baco::config::ScannerConfig::default(),
        );

        // Test with a non-existent file (should return empty, not error)
        let result = analyzer.analyze_file(std::path::Path::new("/nonexistent/file.c")).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_with_context_prefix() {
        let languages = vec!["c".to_string()];
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
        };

        let client = LlmClient::new(llm_config);
        let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
        let _analyzer = LlmAnalyzer::new(
            client,
            languages.clone(),
            1024,
            &baco::config::ScannerConfig::default(),
        )
        .with_context_prefix("RAG context here");

        // Just verify builder pattern works
        // (no assertion needed - test passes if no panic)
    }
}