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

    fn create_analyzer() -> LlmAnalyzer {
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
        LlmAnalyzer::new(
            client,
            languages,
            1024,
            &baco::config::ScannerConfig::default(),
        )
    }

    #[tokio::test]
    async fn test_parse_llm_response_various_formats() {
        let analyzer = create_analyzer();

        // Test 1: with description
        {
            let json_response = r#"[{"severity": "critical", "title": "Buffer overflow test", "description": "This is a test vulnerability description with 50+ characters", "line": 10, "cwe_id": "CWE-120", "exploit_scenario": "Test exploit", "attack_complexity": "low", "impact": "RCE", "fix_code": "Fixed code", "diff_hunk": "@@ -10,5 +10,7 @@", "recommendation": "Use strncpy"}]"#;
            let result: Result<_, String> =
                analyzer.parse_llm_response(json_response, "test.c", "test-model");
            assert!(result.is_ok());
            let findings = result.unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].title, "Buffer overflow test");
            assert!(findings[0].description.len() > 50);
        }

        // Test 2: with empty description
        {
            let json_response = r#"[{"severity": "medium", "title": "Test finding", "description": "", "line": 15, "cwe_id": "CWE-78", "exploit_scenario": "Test", "attack_complexity": "medium", "impact": "High", "fix_code": "Fix", "diff_hunk": "@@ -15,5 +15,7 @@", "recommendation": "Validate input"}]"#;
            let result: Result<_, String> =
                analyzer.parse_llm_response(json_response, "test.c", "test-model");
            assert!(result.is_ok());
            let findings = result.unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].description.len(), 0);
        }

        // Test 3: with markdown fences
        {
            let json_response = r#"```json
[{"severity": "high", "title": "Code injection", "description": "Test description for code injection vulnerability", "line": 20, "cwe_id": "CWE-94", "exploit_scenario": "Test", "attack_complexity": "low", "impact": "RCE", "fix_code": "Fix", "diff_hunk": "@@ -20,5 +20,7 @@", "recommendation": "Sanitize input"}]
```"#;
            let result: Result<_, String> =
                analyzer.parse_llm_response(json_response, "test.c", "test-model");
            assert!(result.is_ok());
            let findings = result.unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].title, "Code injection");
            assert_eq!(
                findings[0].description,
                "Test description for code injection vulnerability"
            );
        }

        // Test 4: multiple findings
        {
            let json_response = r#"[{"severity": "critical", "title": "Buffer overflow", "description": "Buffer overflow vulnerability", "line": 10}, {"severity": "high", "title": "SQL injection", "description": "SQL injection vulnerability", "line": 20}, {"severity": "medium", "title": "XSS", "description": "Cross-site scripting", "line": 30}]"#;
            let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
            assert!(result.is_ok());
            let findings = result.unwrap();
            assert_eq!(findings.len(), 3);
        }

        // Test 5: invalid JSON
        {
            let json_response = "not valid json";
            let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
            assert!(result.is_ok());
            let findings = result.unwrap();
            assert_eq!(findings.len(), 0);
        }

        // Test 6: missing fields
        {
            let json_response = r#"[{"severity": "high", "title": "Missing line"}]"#;
            let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
            assert!(result.is_ok());
            let findings = result.unwrap();
            assert_eq!(findings.len(), 0);
        }
    }

    #[test]
    fn test_format_cwe_specs_various_cases() {
        let test_cases = vec![
            ("empty", vec![], ""),
            (
                "single",
                vec![CweDocument {
                    cwe_id: "CWE-120".to_string(),
                    name: "Buffer Copy without Checking Size".to_string(),
                    description: "Classic buffer overflow".to_string(),
                    examples: vec!["gets() is unsafe".to_string()],
                    mitigation: "Use strncpy()".to_string(),
                }],
                "CWE-120",
            ),
            (
                "multiple",
                vec![
                    CweDocument {
                        cwe_id: "CWE-120".to_string(),
                        name: "Buffer Copy".to_string(),
                        description: "Description 1".to_string(),
                        examples: vec![],
                        mitigation: "Mitigation 1".to_string(),
                    },
                    CweDocument {
                        cwe_id: "CWE-78".to_string(),
                        name: "OS Command Injection".to_string(),
                        description: "Description 2".to_string(),
                        examples: vec![],
                        mitigation: "Mitigation 2".to_string(),
                    },
                ],
                "CWE-120",
            ),
        ];

        for (name, docs, expected_contains) in test_cases {
            let formatted = format_cwe_specs(&docs.iter().collect::<Vec<_>>());
            if !expected_contains.is_empty() {
                assert!(
                    formatted.contains(expected_contains),
                    "Should contain {} for {}",
                    expected_contains,
                    name
                );
            } else {
                assert_eq!(
                    formatted, "",
                    "Empty should return empty string for {}",
                    name
                );
            }
        }
    }

    #[test]
    fn test_extract_cwe_id_various_cases() {
        let test_cases = vec![
            (
                "found",
                "This vulnerability relates to CWE-120 buffer overflow",
                Some("CWE-120"),
            ),
            ("not_found", "This is a generic vulnerability", None),
            ("multiple", "Related to CWE-120 and CWE-78", Some("CWE-120")),
        ];

        for (name, description, expected) in test_cases {
            let result = extract_cwe_id(description);
            assert_eq!(
                result,
                expected.map(|s| s.to_string()),
                "Failed for {}",
                name
            );
        }
    }

    #[test]
    fn test_generate_recommendation_various_types() {
        let test_cases = vec![
            (
                "sql_injection",
                "SQL Injection",
                "User input in SQL query",
                vec!["parameterized", "prepared statements"],
            ),
            (
                "command_injection",
                "Command Injection",
                "Shell command execution",
                vec!["shell command", "validate"],
            ),
            (
                "xss",
                "XSS",
                "Cross-site scripting",
                vec!["Escape", "encoding"],
            ),
            (
                "buffer_overflow",
                "Buffer Overflow",
                "Memory corruption",
                vec!["bounds checking"],
            ),
            (
                "use_after_free",
                "Use After Free",
                "UAF vulnerability",
                vec!["smart pointers", "nullification"],
            ),
            (
                "null_dereference",
                "Null Pointer Dereference",
                "NULL access",
                vec!["null", "Option"],
            ),
            (
                "format_string",
                "Format String",
                "printf vulnerability",
                vec!["format specifiers"],
            ),
            (
                "generic_user_input",
                "Generic",
                "User input not validated",
                vec!["Validate", "sanitize"],
            ),
            (
                "generic_untrusted",
                "Generic",
                "Untrusted data",
                vec!["untrusted", "validation"],
            ),
            (
                "fallback",
                "Unknown Type",
                "Some description",
                vec!["Review", "Unknown Type"],
            ),
        ];

        for (name, vuln_type, description, expected_keywords) in test_cases {
            let rec = generate_recommendation(vuln_type, description);
            for keyword in expected_keywords {
                assert!(
                    rec.contains(keyword),
                    "Recommendation for {} should contain '{}': got {}",
                    name,
                    keyword,
                    rec
                );
            }
        }
    }

    #[tokio::test]
    async fn test_truncate_code_various_sizes() {
        let analyzer = create_analyzer();

        // Test 1: within limit
        {
            let code = "int x = 42;";
            let truncated = analyzer.truncate_code(code);
            assert_eq!(truncated, code);
        }

        // Test 2: exceeds limit
        {
            let long_code = "x".repeat(10000);
            let truncated = analyzer.truncate_code(&long_code);
            assert_eq!(&truncated[..8000], "x".repeat(8000));
            assert!(truncated.contains("[truncated"));
            assert!(truncated.contains("2000 chars omitted"));
        }
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
            1,
            &baco::config::ScannerConfig::default(),
        );

        let result = analyzer
            .analyze_file(std::path::Path::new("/nonexistent/file.c"))
            .await;
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
    }
}
