#[cfg(test)]
mod tests {
    use baco::llm::LlmClient;
    use baco::llm::LlmConfig;
    use baco::llm_analysis::LlmAnalyzer;

    use baco::llm_metrics::LlmMetricsTracker;
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
}
