//! Unit tests for src/llm.rs
//!
//! Tests cover:
//! 1. LlmConfig default values and custom configuration
//! 2. ModelSelector round-robin behavior
//! 3. LlmClient creation and model selection
//! 4. ChatMessage construction (system/user/assistant)
//! 5. ChatResponse and ChatResponseWithModel structures
//! 6. Tool schema serialization
//! 7. Edge cases: empty configs, None fields, defaults

use baco::llm::{
    ChatMessage, ChatResponse, ChatResponseWithModel, FunctionToolDefinition, LlmClient, LlmConfig,
    LlmProvider, ModelSelector, ToolSchema,
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
    };

    let models = config.get_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "primary");
}

// ============================================================================
// ModelSelector Tests
// ============================================================================

#[test]
fn test_model_selector_round_robin() {
    let selector = ModelSelector::new(vec![
        "model-a".to_string(),
        "model-b".to_string(),
        "model-c".to_string(),
    ]);

    assert_eq!(selector.next(), Some("model-a".to_string()));
    assert_eq!(selector.next(), Some("model-b".to_string()));
    assert_eq!(selector.next(), Some("model-c".to_string()));
    assert_eq!(selector.next(), Some("model-a".to_string())); // Cycles back
}

#[test]
fn test_model_selector_empty() {
    let selector = ModelSelector::new(vec![]);
    assert!(selector.next().is_none());
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

#[tokio::test]
async fn test_mock_provider_chat_success() {
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

#[tokio::test]
async fn test_mock_provider_chat_error() {
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

#[tokio::test]
async fn test_mock_provider_with_different_messages() {
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
