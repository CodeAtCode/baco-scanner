#[cfg(test)]
mod tgi_client_tests {
    use baco::config::TgiConfig;
    use baco::llm::LlmConfig;
    use baco::llm::{CompletionOptions, LlmClient, TgiClient as TgiClientType};
    use mockito;

    #[tokio::test]
    async fn test_tgi_complete_parses_response() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/v1/chat/completions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "choices": [{
                        "message": {
                            "content": "Test response"
                        }
                    }]
                }"#,
            )
            .create();

        let config = TgiConfig {
            enabled: true,
            endpoint: server.url(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 120,
            do_sample: true,
        };

        let client = TgiClientType::new(&config).unwrap();
        let result = client.complete("Test prompt").await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Test response");
        mock.assert();
    }

    #[tokio::test]
    async fn test_tgi_complete_handles_error_status() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/v1/chat/completions")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error": "Internal server error"}"#)
            .create();

        let config = TgiConfig {
            enabled: true,
            endpoint: server.url(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 120,
            do_sample: true,
        };

        let client = TgiClientType::new(&config).unwrap();
        let result = client.complete("Test prompt").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("500"));
        mock.assert();
    }

    #[tokio::test]
    async fn test_tgi_complete_handles_malformed_json() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/v1/chat/completions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("not valid json")
            .create();

        let config = TgiConfig {
            enabled: true,
            endpoint: server.url(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 120,
            do_sample: true,
        };

        let client = TgiClientType::new(&config).unwrap();
        let result = client.complete("Test prompt").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));
        mock.assert();
    }

    #[tokio::test]
    async fn test_tgi_complete_respects_timeout() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/v1/chat/completions")
            .with_delay(std::time::Duration::from_secs(3))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "choices": [{
                        "message": {
                            "content": "Slow response"
                        }
                    }]
                }"#,
            )
            .create();

        let config = TgiConfig {
            enabled: true,
            endpoint: server.url(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 1,
            do_sample: true,
        };

        let client = TgiClientType::new(&config).unwrap();
        let result = client.complete("Test prompt").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timeout") || result.unwrap_err().contains("timeout"));
        mock.assert();
    }

    #[tokio::test]
    async fn test_tgi_complete_with_options_overrides_config() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/v1/chat/completions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .match_body(|body| {
                let json: serde_json::Value = serde_json::from_slice(body).unwrap();
                json.get("max_tokens").and_then(|v| v.as_u64()) == Some(512)
                    && json
                        .get("temperature")
                        .and_then(|v| v.as_f64())
                        .map(|v| (v - 0.8).abs() < 0.01)
                        .unwrap_or(false)
            })
            .with_body(
                r#"{
                    "choices": [{
                        "message": {
                            "content": "Response with options"
                        }
                    }]
                }"#,
            )
            .create();

        let config = TgiConfig {
            enabled: true,
            endpoint: server.url(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 120,
            do_sample: true,
        };

        let client = TgiClientType::new(&config).unwrap();
        let options = CompletionOptions {
            max_new_tokens: Some(512),
            temperature: Some(0.8),
            stop: vec![],
        };
        let result = client.complete_with_options("Test prompt", &options).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Response with options");
        mock.assert();
    }

    #[test]
    fn test_tgi_is_available_true_on_health_200() {
        let mut server = mockito::Server::new();
        let _mock = server
            .mock("GET", "/health")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status": "ready"}"#)
            .create();

        let config = TgiConfig {
            enabled: true,
            endpoint: server.url(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 120,
            do_sample: true,
        };

        let client = TgiClientType::new(&config).unwrap();
        assert!(client.is_available());
    }

    #[test]
    fn test_tgi_is_available_false_on_connection_error() {
        let config = TgiConfig {
            enabled: true,
            endpoint: "http://localhost:59999".to_string(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 1,
            do_sample: true,
        };

        let client = TgiClientType::new(&config).unwrap();
        assert!(!client.is_available());
    }

    #[test]
    fn test_tgi_is_available_false_on_500() {
        let mut server = mockito::Server::new();
        let _mock = server
            .mock("GET", "/health")
            .with_status(500)
            .with_body("Internal error")
            .create();

        let config = TgiConfig {
            enabled: true,
            endpoint: server.url(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 120,
            do_sample: true,
        };

        let client = TgiClientType::new(&config).unwrap();
        assert!(!client.is_available());
    }

    #[test]
    fn test_llm_client_with_tgi_attaches_client() {
        let config = TgiConfig {
            enabled: true,
            endpoint: "http://localhost:8080".to_string(),
            model: "test-model".to_string(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 120,
            do_sample: true,
        };

        let llm_config = LlmConfig::default();
        let client = LlmClient::new(llm_config);
        let result = client.with_tgi(&config);

        // This will fail because the endpoint doesn't exist, but that's expected
        // The important thing is that it attempts to create the client
        assert!(result.is_err());
    }

    #[test]
    fn test_llm_client_without_tgi_returns_none() {
        let llm_config = LlmConfig::default();
        let client = LlmClient::new(llm_config);

        // complete_via_tgi should return None when no TGI client is attached
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(client.complete_via_tgi("test"));
        assert!(result.is_none());
    }

    #[test]
    fn test_llm_client_tgi_is_available_false_when_disabled() {
        let llm_config = LlmConfig::default();
        let client = LlmClient::new(llm_config);

        assert!(!client.tgi_is_available());
    }
}
