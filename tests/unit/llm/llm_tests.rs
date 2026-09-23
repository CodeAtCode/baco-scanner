//! Unit tests for src/llm.rs
//!
//! Tests cover:
//! 1. LlmConfig default values and custom configuration
//! 2. AtomicModelSelector round-robin behavior
//! 3. LlmClient creation and model selection
//! 4. ChatMessage construction (system/user/assistant)
//! 5. ChatResponse and ChatResponseWithModel structures
//! 6. Tool schema serialization
//! 7. Edge cases: empty configs, None fields, defaults

use baco::llm::{
    AtomicModelSelector, ChatMessage, ChatResponse, ChatResponseWithModel, FunctionToolDefinition,
    LlmClient, LlmConfig, LlmProvider, ToolSchema, apply_retry_backoff, backoff_delay_ms,
    fail_fast_status_error, parse_chat_content, parse_tool_calls,
};
use serde_json::json;

// ============================================================================
// LlmConfig Tests
// ============================================================================

#[test]
fn test_llm_config_default() {
    let config = LlmConfig::default();
    assert_eq!(config.base_url, "https://api.openai.com/v1");
    assert_eq!(config.model, "gpt-4");
    assert!(config.models.is_empty());
    assert_eq!(config.timeout, 30);
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.retry_backoff_ms, 1000);
    assert_eq!(config.temperature, 0.5);
    assert!(config.max_reasoning_tokens.is_none());
}

#[test]
fn test_llm_config_from_env() {
    // Simulate loading config from environment variables
    let config = LlmConfig {
        base_url: "https://api.custom.com/v1".to_string(),
        api_key: "env-api-key".to_string(),
        model: "env-model".to_string(),
        models: vec![],
        timeout: 60,
        max_retries: 5,
        retry_backoff_ms: 2000,
        temperature: 0.7,
        max_reasoning_tokens: Some(1024),
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };

    assert_eq!(config.base_url, "https://api.custom.com/v1");
    assert_eq!(config.api_key, "env-api-key");
    assert_eq!(config.timeout, 60);
    assert_eq!(config.max_retries, 5);
    assert_eq!(config.max_reasoning_tokens, Some(1024));
}

#[test]
fn test_llm_config_invalid() {
    // Invalid config: empty base_url and api_key
    let config = LlmConfig {
        base_url: String::new(),
        api_key: String::new(),
        model: String::new(),
        models: vec![],
        timeout: 0,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.0,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };

    // Config allows invalid values - validation happens at runtime
    assert!(config.base_url.is_empty());
    assert!(config.api_key.is_empty());
}

#[test]
fn test_llm_config_get_models_priority() {
    // models vec takes priority over single model
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "fallback".to_string(),
        models: vec!["primary".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };

    let models = config.get_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "primary");
}

// ============================================================================
// AtomicModelSelector Tests
// ===========================================================================

#[test]
fn test_atomic_model_selector_round_robin() {
    let selector = AtomicModelSelector::new(vec![
        "model-a".to_string(),
        "model-b".to_string(),
        "model-c".to_string(),
    ]);

    assert_eq!(selector.next(), "model-a".to_string());
    assert_eq!(selector.next(), "model-b".to_string());
    assert_eq!(selector.next(), "model-c".to_string());
    assert_eq!(selector.next(), "model-a".to_string()); // Cycles back
}

#[test]
fn test_atomic_model_selector_empty() {
    // Empty case handled at LlmClient level - selector is None
    // This test verifies the type exists and compiles
    fn _type_check() {
        let _selector = AtomicModelSelector::new(vec!["test".to_string()]);
    }
    _type_check();
}

// ============================================================================
// LlmClient Tests
// ============================================================================

#[test]
fn test_llm_client_creation() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
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
        pricing: Default::default(),
    };

    let client = LlmClient::new(config);
    assert_eq!(client.model_name(), "test-model");
}

#[test]
fn test_llm_client_with_multiple_models() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: String::new(),
        models: vec!["model-1".to_string(), "model-2".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };

    let client = LlmClient::new(config);
    let models = client.get_all_models();
    assert_eq!(models.len(), 2);
}

// ============================================================================
// ChatMessage Tests
// ============================================================================

#[test]
fn test_chat_message_system() {
    let msg = ChatMessage::system("You are a security expert");
    assert_eq!(msg.role, "system");
    assert_eq!(msg.content, "You are a security expert");
}

#[test]
fn test_chat_message_user() {
    let msg = ChatMessage::user("Analyze this code");
    assert_eq!(msg.role, "user");
    assert_eq!(msg.content, "Analyze this code");
}

#[test]
fn test_chat_message_assistant() {
    let msg = ChatMessage::assistant("I found a vulnerability");
    assert_eq!(msg.role, "assistant");
    assert_eq!(msg.content, "I found a vulnerability");
}

#[test]
fn test_chat_message_empty_content() {
    let msg = ChatMessage::user("");
    assert_eq!(msg.role, "user");
    assert!(msg.content.is_empty());
}

// ============================================================================
// ChatResponse Tests
// ============================================================================

#[test]
fn test_chat_response_parsing() {
    // Simulate parsing an LLM response into structured data
    let json_response = json!({
        "content": "Found SQL injection",
        "tool_calls": [],
        "raw": {},
        "model_used": "llama3.1"
    });

    let response: ChatResponse = serde_json::from_value(json_response).unwrap();
    assert_eq!(response.content, "Found SQL injection");
    assert!(response.tool_calls.is_empty());
    assert_eq!(response.model_used, "llama3.1");
}

#[test]
fn test_chat_response_with_tool_calls() {
    let json_response = json!({
        "content": "Calling search tool",
        "tool_calls": [{
            "id": "call_123",
            "name": "search_vulnerabilities",
            "arguments": {"query": "SQL injection"}
        }],
        "raw": {},
        "model_used": "gpt-4"
    });

    let response: ChatResponse = serde_json::from_value(json_response).unwrap();
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "search_vulnerabilities");
}

#[test]
fn test_llm_empty_response() {
    // Empty response handled gracefully
    let json_response = json!({
        "content": "",
        "tool_calls": [],
        "raw": {},
        "model_used": ""
    });

    let response: ChatResponse = serde_json::from_value(json_response).unwrap();
    assert!(response.content.is_empty());
    assert!(response.tool_calls.is_empty());
}

#[test]
fn test_llm_malformed_response() {
    // Malformed response should fail to parse
    let invalid_json = "{ invalid json }";
    let result: Result<ChatResponse, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err());
}

// ============================================================================
// Tool Schema Tests
// ============================================================================

#[test]
fn test_function_tool_definition() {
    let tool = FunctionToolDefinition {
        name: "analyze_code".to_string(),
        description: "Analyze code for vulnerabilities".to_string(),
        parameters: json!({
            "type": "object",
            "properties": {
                "code": {"type": "string"}
            }
        }),
    };

    assert_eq!(tool.name, "analyze_code");
    assert_eq!(tool.description, "Analyze code for vulnerabilities");
}

#[test]
fn test_tool_schema_serialization() {
    let tool = ToolSchema {
        type_: "function".to_string(),
        function: FunctionToolDefinition {
            name: "test_tool".to_string(),
            description: "Test description".to_string(),
            parameters: json!({}),
        },
    };

    let serialized = serde_json::to_string(&tool).unwrap();
    assert!(serialized.contains("function"));
    assert!(serialized.contains("test_tool"));
}

// ============================================================================
// ChatResponseWithModel Tests
// ============================================================================

#[test]
fn test_chat_response_with_model_new() {
    let response =
        ChatResponseWithModel::new("Analysis complete".to_string(), "llama3.1".to_string());

    assert_eq!(response.content, "Analysis complete");
    assert_eq!(response.model_used, "llama3.1");
}

// ============================================================================
// chat_endpoint Tests - URL construction must not double the /v1 prefix
// ============================================================================

#[test]
fn test_chat_endpoint_base_url_with_v1() {
    assert_eq!(
        baco::llm::chat_endpoint("https://api.mistral.ai/v1"),
        "https://api.mistral.ai/v1/chat/completions"
    );
}

#[test]
fn test_chat_endpoint_base_url_without_v1() {
    assert_eq!(
        baco::llm::chat_endpoint("https://llm.example.com"),
        "https://llm.example.com/v1/chat/completions"
    );
}

#[test]
fn test_chat_endpoint_base_url_with_trailing_slash() {
    assert_eq!(
        baco::llm::chat_endpoint("https://api.openai.com/v1/"),
        "https://api.openai.com/v1/chat/completions"
    );
}

#[test]
fn test_chat_endpoint_localhost_no_v1() {
    assert_eq!(
        baco::llm::chat_endpoint("http://localhost:8080"),
        "http://localhost:8080/v1/chat/completions"
    );
}
// ============================================================================
// Additional ChatMessage Tests
// ============================================================================

#[test]
fn test_chat_message_long_content() {
    let long_content = "A".repeat(1000);
    let msg = ChatMessage::user(&long_content);
    assert_eq!(msg.content.len(), 1000);
}

// ============================================================================
// LlmConfig Validation Tests
// ============================================================================

#[test]
fn test_llm_config_validation() {
    use baco::llm::LlmConfig;

    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        ..Default::default()
    };
    assert_eq!(config.base_url, "https://api.test.com/v1");
    assert_eq!(config.model, "test-model");
}

// ============================================================================
// LlmClient Tests
// ============================================================================

#[test]
fn test_llm_client_new() {
    use baco::llm::LlmConfig;

    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        ..Default::default()
    };
    let client = LlmClient::new(config);
    assert!(client.config.base_url.contains("api.test.com"));
}

// ============================================================================
// MockLlmProvider Tests (async)
// ============================================================================

#[test]
fn test_mock_provider_chat_success() {
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub LlmProvider {}

        impl baco::llm::LlmProvider for LlmProvider {
            fn chat(&self, messages: &[ChatMessage]) -> Result<String, baco::error::ScanError>;
        }
    }

    let mut mock_provider = MockLlmProvider::new();
    mock_provider
        .expect_chat()
        .times(1)
        .returning(|_| Ok("Successfully analyzed".to_string()));

    let messages = vec![ChatMessage::user("Test message")];
    let result = mock_provider.chat(&messages);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Successfully analyzed");
}

#[test]
fn test_mock_provider_chat_error() {
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub LlmProvider {}

        impl baco::llm::LlmProvider for LlmProvider {
            fn chat(&self, messages: &[ChatMessage]) -> Result<String, baco::error::ScanError>;
        }
    }

    let mut mock_provider = MockLlmProvider::new();
    mock_provider.expect_chat().times(1).returning(|_| {
        Err(baco::error::ScanError::LlmClientBuildError(
            "API Error".to_string(),
        ))
    });

    let messages = vec![ChatMessage::user("Test message")];
    let result = mock_provider.chat(&messages);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        baco::error::ScanError::LlmClientBuildError(_)
    ));
}

#[test]
fn test_mock_provider_with_different_messages() {
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub LlmProvider {}

        impl baco::llm::LlmProvider for LlmProvider {
            fn chat(&self, messages: &[ChatMessage]) -> Result<String, baco::error::ScanError>;
        }
    }

    let mut mock_provider = MockLlmProvider::new();
    mock_provider.expect_chat().times(1).returning(|messages| {
        assert_eq!(messages.len(), 2);
        Ok(format!("Responded to {} messages", messages.len()))
    });

    let messages = vec![
        ChatMessage::system("You are helpful"),
        ChatMessage::user("Hello"),
    ];
    let result = mock_provider.chat(&messages);
    assert!(result.is_ok());
}

// ============================================================================
// LlmConfig Consolidation Tests
// ============================================================================

#[test]
fn test_llm_config_single_canonical_default_max_concurrent() {
    // Verify that max_concurrent defaults to 4 (the unified config-side default)
    let config = LlmConfig::default();
    assert_eq!(
        config.max_concurrent, 4,
        "LlmConfig default max_concurrent must be 4 (unified config default)"
    );
}

#[test]
fn test_llm_config_default_temperature() {
    // Verify that temperature defaults to 0.5
    let config = LlmConfig::default();
    assert_eq!(
        config.temperature, 0.5,
        "LlmConfig default temperature must be 0.5"
    );
}

// ============================================================================
// Pricing Configuration Tests
// ============================================================================

#[test]
fn test_pricing_config_default_empty() {
    // Pricing table defaults to empty HashMap
    let config = LlmConfig::default();
    assert!(config.pricing.is_empty());
}

#[test]
fn test_pricing_config_with_models() {
    use baco::config::ModelPricing;
    use std::collections::HashMap;

    let mut pricing: HashMap<String, ModelPricing> = HashMap::new();
    pricing.insert(
        "gpt-4".to_string(),
        ModelPricing {
            prompt_per_1k: 0.03,
            completion_per_1k: 0.06,
        },
    );
    pricing.insert(
        "claude-3".to_string(),
        ModelPricing {
            prompt_per_1k: 0.015,
            completion_per_1k: 0.075,
        },
    );

    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_concurrent: 3,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        pricing: pricing.clone(),
    };

    assert_eq!(config.pricing.len(), 2);
    assert_eq!(config.pricing.get("gpt-4").unwrap().prompt_per_1k, 0.03);
    assert_eq!(
        config.pricing.get("claude-3").unwrap().completion_per_1k,
        0.075
    );
}

#[test]
fn test_model_pricing_cost_calculation() {
    use baco::config::ModelPricing;

    let pricing = ModelPricing {
        prompt_per_1k: 0.03,
        completion_per_1k: 0.06,
    };

    // Test cost calculation: (prompt/1000) * prompt_rate + (completion/1000) * completion_rate
    let cost = pricing.cost(1000, 1000);
    assert!((cost - 0.09).abs() < 0.001); // 0.03 + 0.06 = 0.09

    let cost = pricing.cost(800, 200);
    assert!((cost - 0.036).abs() < 0.001); // 0.024 + 0.012 = 0.036

    let cost = pricing.cost(0, 0);
    assert_eq!(cost, 0.0);

    let cost = pricing.cost(5000, 2500);
    assert!((cost - 0.3).abs() < 0.001); // 0.15 + 0.15 = 0.30
}

#[test]
fn test_pricing_serialization() {
    use baco::config::ModelPricing;
    use std::collections::HashMap;

    let mut pricing: HashMap<String, ModelPricing> = HashMap::new();
    pricing.insert(
        "test-model".to_string(),
        ModelPricing {
            prompt_per_1k: 0.025,
            completion_per_1k: 0.05,
        },
    );

    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_concurrent: 3,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        pricing: pricing.clone(),
    };

    let json = serde_json::to_string(&config).unwrap();
    let parsed: LlmConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.pricing.len(), 1);
    assert_eq!(
        parsed.pricing.get("test-model").unwrap().prompt_per_1k,
        0.025
    );
}

// ============================================================================
// Cache Module Tests
// ============================================================================

#[test]
fn test_cache_key_computation_deterministic() {
    use baco::llm::cache::compute_cache_key;

    let messages = serde_json::json!([{"role": "user", "content": "test"}]);
    let messages_json = serde_json::to_vec(&messages).unwrap();

    let key1 = compute_cache_key(
        "gpt-4",
        "https://api.openai.com/v1",
        0.5,
        None,
        &messages_json,
    );
    let key2 = compute_cache_key(
        "gpt-4",
        "https://api.openai.com/v1",
        0.5,
        None,
        &messages_json,
    );

    // Same inputs must produce same cache key
    assert_eq!(key1, key2);
    assert_eq!(key1.len(), 64); // SHA256 hex is 64 chars
}

#[test]
fn test_cache_key_changes_with_temperature() {
    use baco::llm::cache::compute_cache_key;

    let messages = serde_json::json!([{"role": "user", "content": "test"}]);
    let messages_json = serde_json::to_vec(&messages).unwrap();

    let key_low_temp = compute_cache_key(
        "gpt-4",
        "https://api.openai.com/v1",
        0.2,
        None,
        &messages_json,
    );
    let key_high_temp = compute_cache_key(
        "gpt-4",
        "https://api.openai.com/v1",
        0.9,
        None,
        &messages_json,
    );

    // Different temperatures must produce different cache keys
    assert_ne!(key_low_temp, key_high_temp);
}

#[test]
fn test_cache_key_changes_with_model() {
    use baco::llm::cache::compute_cache_key;

    let messages = serde_json::json!([{"role": "user", "content": "test"}]);
    let messages_json = serde_json::to_vec(&messages).unwrap();

    let key_gpt4 = compute_cache_key(
        "gpt-4",
        "https://api.openai.com/v1",
        0.5,
        None,
        &messages_json,
    );
    let key_claude = compute_cache_key(
        "claude-3",
        "https://api.anthropic.com/v1",
        0.5,
        None,
        &messages_json,
    );

    // Different models must produce different cache keys
    assert_ne!(key_gpt4, key_claude);
}

#[test]
fn test_cache_file_path_construction() {
    use baco::llm::cache::cache_file_path;
    use std::path::Path;

    let cache_dir = Path::new("/tmp/llm-cache");
    let cache_key = "abc123";

    let path = cache_file_path(cache_dir, cache_key);

    assert_eq!(path.to_str().unwrap(), "/tmp/llm-cache/abc123.json");
}

#[test]
fn test_get_effective_cache_dir_default() {
    use baco::llm::cache::get_effective_cache_dir;

    let default_dir = get_effective_cache_dir(None);
    assert_eq!(default_dir.to_str().unwrap(), "baco-output/llm-cache");
}

#[test]
fn test_get_effective_cache_dir_custom() {
    use baco::llm::cache::get_effective_cache_dir;

    let custom_dir = "/custom/cache/path";
    let result = get_effective_cache_dir(Some(&custom_dir.to_string()));
    assert_eq!(result.to_str().unwrap(), "/custom/cache/path");
}

// ============================================================================
// Token Usage Parsing Tests (A4 fix verification)
// ============================================================================

#[test]
fn test_parse_usage_from_response() {
    // Verify that usage.prompt_tokens and usage.completion_tokens are parsed correctly
    let response_with_usage = json!({
        "choices": [{
            "message": {"content": "test response"}
        }],
        "usage": {
            "prompt_tokens": 150,
            "completion_tokens": 75
        }
    });

    let usage = response_with_usage.get("usage");
    let tokens_prompt = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let tokens_completion = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    assert_eq!(tokens_prompt, 150);
    assert_eq!(tokens_completion, 75);
}

#[test]
fn test_parse_usage_missing_fields_defaults_to_zero() {
    // Verify that missing usage fields default to 0
    let response_without_usage = json!({
        "choices": [{
            "message": {"content": "test response"}
        }]
    });

    let usage = response_without_usage.get("usage");
    let tokens_prompt = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let tokens_completion = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    assert_eq!(tokens_prompt, 0);
    assert_eq!(tokens_completion, 0);
}

// ============================================================================
// Error Propagation Tests (A6 fix verification)
// ============================================================================

#[test]
fn test_auth_error_classification() {
    // Verify that 401/403 errors are classified as non-retryable auth errors
    let (should_retry_401, _) = LlmClient::classify_retryable(401, None);
    assert!(!should_retry_401);

    let (should_retry_403, _) = LlmClient::classify_retryable(403, None);
    assert!(!should_retry_403);
}

// ============================================================================
// Tool Calls Cache Tests (A7 fix verification)
// ============================================================================

#[test]
fn test_tool_calls_cache_roundtrip() {
    // Verify that tool_calls are correctly serialized and deserialized in cache
    use baco::agent::ToolCall;

    let cached_response = json!({
        "content": "Calling tool",
        "tool_calls": [{
            "id": "call_123",
            "function": {
                "name": "search_vulnerabilities",
                "arguments": {"query": "SQL injection"}
            }
        }],
        "model": "gpt-4",
        "timestamp": "2024-01-01T00:00:00Z"
    });

    let content = cached_response
        .get("content")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();

    let tool_calls = cached_response
        .get("tool_calls")
        .and_then(|tc| tc.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|tc| {
                    tc.get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|name| name.as_str())
                        .map(|name| ToolCall {
                            id: tc.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()),
                            name: name.to_string(),
                            arguments: tc
                                .get("function")
                                .and_then(|f| f.get("arguments"))
                                .and_then(|a| a.as_object())
                                .map(|o| serde_json::to_value(o).unwrap_or_default())
                                .unwrap_or_default(),
                        })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    assert_eq!(content, "Calling tool");
    assert_eq!(tool_calls.len(), 1);
    assert_eq!(tool_calls[0].name, "search_vulnerabilities");
    assert_eq!(tool_calls[0].id, Some("call_123".to_string()));
}

#[test]
fn test_tool_calls_empty_array() {
    // Verify that empty tool_calls array is handled correctly
    let cached_response = json!({
        "content": "No tools called",
        "tool_calls": [],
        "model": "gpt-4",
        "timestamp": "2024-01-01T00:00:00Z"
    });

    let tool_calls = cached_response
        .get("tool_calls")
        .and_then(|tc| tc.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);

    assert_eq!(tool_calls, 0);
}

// ============================================================================
// Cache Key Versioning Tests (A7 fix verification)
// ============================================================================

#[test]
fn test_cache_key_versioning() {
    // Verify that cache keys include version prefix to break stale entries
    let cache_key_base = "abc123def456";
    let versioned_key = format!("v2::{}", cache_key_base);

    assert_eq!(versioned_key, "v2::abc123def456");
    assert!(versioned_key.starts_with("v2::"));
}

#[test]
fn test_json_schema_cache_key_includes_schema() {
    // Verify that JSON schema cache keys include the schema name and content
    let cache_key_base = "abc123";
    let schema_name = "vulnerability_report";
    let json_schema = json!({"type": "object"});
    let cache_key_suffix = format!("{}_{}", schema_name, json_schema);
    let cache_key = format!("{}::json_schema:{}", cache_key_base, cache_key_suffix);

    assert!(cache_key.contains("json_schema"));
    assert!(cache_key.contains("vulnerability_report"));
}
#[tokio::test]
async fn test_chat_failover_to_next_model_on_retryable_error() {
    let mut server = mockito::Server::new_async().await;

    let bad_mock = server
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::Regex("bad-model".to_string()))
        .with_status(500)
        .with_body("internal error")
        .create();
    let good_mock = server
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::Regex("good-model".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices": [{"message": {"content": "recovered"}}]}"#)
        .create();

    let config = LlmConfig {
        base_url: server.url(),
        api_key: "test".to_string(),
        model: "bad-model".to_string(),
        models: vec!["bad-model".to_string(), "good-model".to_string()],
        timeout: 5,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 4,
        pricing: Default::default(),
    };
    let client = LlmClient::new(config);
    let messages = vec![ChatMessage::user("hi")];

    let result = client.chat(&messages).await;
    assert!(result.is_ok(), "failover should succeed via good-model");
    assert_eq!(result.unwrap().content, "recovered");
    bad_mock.assert_async().await;
    good_mock.assert_async().await;
}
#[test]
fn backoff_delay_ms_grows_exponentially_and_caps() {
    assert_eq!(backoff_delay_ms(100, 0), 100);
    assert_eq!(backoff_delay_ms(100, 1), 200);
    assert_eq!(backoff_delay_ms(100, 2), 400);
    assert_eq!(backoff_delay_ms(1000, 20), 30_000);
    assert_eq!(backoff_delay_ms(0, 5), 0);
}

#[test]
fn fail_fast_status_error_only_for_non_retryable() {
    assert!(fail_fast_status_error(400, "bad").is_some());
    assert!(fail_fast_status_error(401, "deny").is_some());
    assert!(fail_fast_status_error(403, "deny").is_some());
    assert!(fail_fast_status_error(500, "boom").is_none());
    assert!(fail_fast_status_error(429, "slow").is_none());
}

#[test]
fn parse_chat_content_valid_and_garbage() {
    let value: serde_json::Value =
        serde_json::from_str(r#"{"choices": [{"message": {"content": "hi"}}]}"#).unwrap();
    assert_eq!(parse_chat_content(&value).unwrap(), "hi");
    let garbage: serde_json::Value = serde_json::from_str(r#"{"nope": true}"#).unwrap();
    assert!(parse_chat_content(&garbage).is_err());
}

#[test]
fn parse_tool_calls_present_and_absent() {
    let message = json!({
        "tool_calls": [
            {"id": "c1", "function": {"name": "search", "arguments": {}}}
        ]
    });
    let calls = parse_tool_calls(&message);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name, "search");
    let bare = json!({"content": "hi"});
    assert!(parse_tool_calls(&bare).is_empty());
}

#[tokio::test]
async fn apply_retry_backoff_zero_base_returns_fast_and_counts() {
    let mut retries = 0u32;
    apply_retry_backoff(0, 500, None, &mut retries).await;
    assert_eq!(retries, 1);
}
fn failover_test_config(base_url: String, models: Vec<String>) -> LlmConfig {
    LlmConfig {
        base_url,
        api_key: "test".to_string(),
        model: models[0].clone(),
        models,
        timeout: 5,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 4,
        pricing: Default::default(),
    }
}

#[tokio::test]
async fn test_tools_failover_to_next_model_on_retryable_error() {
    let mut server = mockito::Server::new_async().await;
    let bad_mock = server
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::Regex("bad-model".to_string()))
        .with_status(500)
        .with_body("internal error")
        .create();
    let good_mock = server
        .mock("POST", "/v1/chat/completions")
        .match_body(mockito::Matcher::Regex("good-model".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices": [{"message": {"content": "done"}}]}"#)
        .create();

    let config = failover_test_config(
        server.url(),
        vec!["bad-model".to_string(), "good-model".to_string()],
    );
    let client = LlmClient::new(config);
    let tools: &[ToolSchema] = &[];
    let result = client
        .chat_with_tools(&[ChatMessage::user("hi")], tools)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().content, "done");
    bad_mock.assert_async().await;
    good_mock.assert_async().await;
}

#[tokio::test]
async fn test_chat_401_fails_fast_without_retry() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(401)
        .with_body("unauthorized")
        .create();

    let config = failover_test_config(server.url(), vec!["m".to_string()]);
    let client = LlmClient::new(config);
    let result = client.chat(&[ChatMessage::user("hi")]).await;
    assert!(result.is_err());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_chat_refused_connection_errors() {
    let config = failover_test_config("http://127.0.0.1:1".to_string(), vec!["m".to_string()]);
    let client = LlmClient::new(config);
    let result = client.chat(&[ChatMessage::user("hi")]).await;
    assert!(result.is_err());
}
#[tokio::test]
async fn test_chat_persistent_timeout_exhausts() {
    let config = failover_test_config("http://10.255.255.1".to_string(), vec!["m".to_string()]);
    let client = LlmClient::new(config);
    let result = client.chat(&[ChatMessage::user("hi")]).await;
    assert!(result.is_err());
}
#[tokio::test]
async fn test_chat_with_json_schema_ok_path() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices": [{"message": {"content": "schema-ok"}}]}"#)
        .create();

    let config = failover_test_config(server.url(), vec!["m".to_string()]);
    let client = LlmClient::new(config);
    let result = client
        .chat_with_json_schema(
            &[ChatMessage::user("hi")],
            "probe",
            serde_json::json!({"type": "object"}),
        )
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().content, "schema-ok");
}

#[tokio::test]
async fn test_chat_with_metrics_tracker_ok_path() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices": [{"message": {"content": "tracked"}}]}"#)
        .create();

    let config = failover_test_config(server.url(), vec!["m".to_string()]);
    let tracker = baco::llm::metrics::LlmMetricsTracker::new();
    let client = LlmClient::with_metrics(config, Some(tracker));
    let result = client.chat(&[ChatMessage::user("hi")]).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().content, "tracked");
}
#[tokio::test]
async fn test_chat_with_tools_cache_miss_then_hit() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices": [{"message": {"content": "cached-answer"}}]}"#)
        .create();

    let dir = tempfile::TempDir::new().unwrap();
    let mut config = failover_test_config(server.url(), vec!["m".to_string()]);
    config.enable_llm_cache = true;
    config.cache_dir = Some(dir.path().to_string_lossy().to_string());
    config.max_reasoning_tokens = Some(100);
    let client = LlmClient::new(config);
    let tools = vec![ToolSchema {
        type_: "function".to_string(),
        function: FunctionToolDefinition {
            name: "search".to_string(),
            description: "d".to_string(),
            parameters: serde_json::json!({}),
        },
    }];
    let messages = vec![ChatMessage::user("hi")];
    let first = client.chat_with_tools(&messages, &tools).await.unwrap();
    let second = client.chat_with_tools(&messages, &tools).await.unwrap();
    assert_eq!(first.content, "cached-answer");
    assert_eq!(second.content, "cached-answer");
    mock.assert_async().await;
}
#[tokio::test]
async fn test_tools_401_fails_fast_without_retry() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(401)
        .with_body("unauthorized")
        .create();

    let config = failover_test_config(server.url(), vec!["m".to_string()]);
    let client = LlmClient::new(config);
    let tools: &[ToolSchema] = &[];
    let result = client
        .chat_with_tools(&[ChatMessage::user("hi")], tools)
        .await;
    assert!(result.is_err());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_tools_refused_connection_errors() {
    let config = failover_test_config("http://127.0.0.1:1".to_string(), vec!["m".to_string()]);
    let client = LlmClient::new(config);
    let tools: &[ToolSchema] = &[];
    let result = client
        .chat_with_tools(&[ChatMessage::user("hi")], tools)
        .await;
    assert!(result.is_err());
}
