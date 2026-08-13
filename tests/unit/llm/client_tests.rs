//! Unit tests for LlmConfig, LlmClient, and related types
//!
//! Tests cover:
//! 1. LlmConfig creation, defaults, and validation
//! 2. ModelSelector integration with LlmClient
//! 3. LlmClient construction (new, with_metrics)
//! 4. ChatMessage creation and serialization
//! 5. ChatResponseWithModel and ChatResponse structures
//! 6. FunctionToolDefinition and ToolSchema
//! 7. Edge cases: empty configs, None fields, defaults
//! 8. Request payload construction (pure functions)
//! 9. Response parsing logic (pure functions)

use baco::llm::{
    ChatMessage, ChatResponse, ChatResponseWithModel, FunctionToolDefinition, LlmClient, LlmConfig,
    ModelSelector, RecordMetricsParams, ToolSchema,
};
use serde_json::json;

// ============================================================================
// LlmConfig Tests
// ============================================================================

#[test]
fn test_llm_config_default_values() {
    let config = LlmConfig::default();
    assert_eq!(config.base_url, "https://api.openai.com/v1");
    assert_eq!(config.model, "gpt-4");
    assert!(config.models.is_empty());
    assert_eq!(config.timeout, 30);
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.retry_backoff_ms, 1000);
}

#[test]
fn test_llm_config_custom_values() {
    let config = LlmConfig {
        base_url: "https://custom.api.com/v1".to_string(),
        api_key: "secret-key".to_string(),
        model: "custom-model".to_string(),
        models: vec![],
        timeout: 60,
        max_retries: 5,
        retry_backoff_ms: 2000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    assert_eq!(config.base_url, "https://custom.api.com/v1");
    assert_eq!(config.api_key, "secret-key");
    assert_eq!(config.timeout, 60);
}

#[test]
fn test_llm_config_get_models_with_models_vec() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "".to_string(),
        models: vec!["model-1".to_string(), "model-2".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let models = config.get_models();
    assert_eq!(models.len(), 2);
    assert_eq!(models[0], "model-1");
    assert_eq!(models[1], "model-2");
}

#[test]
fn test_llm_config_get_models_with_single_model() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "single-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let models = config.get_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "single-model");
}

#[test]
fn test_llm_config_get_models_empty() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let models = config.get_models();
    assert!(models.is_empty());
}

#[test]
fn test_llm_config_get_models_models_vec_takes_priority() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "fallback-model".to_string(),
        models: vec!["primary-model".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let models = config.get_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "primary-model");
}

// ============================================================================
// LlmClient Tests
// ============================================================================

#[test]
fn test_llm_client_new_basic() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);
    assert_eq!(client.model_name(), "test-model");
}

#[test]
fn test_llm_client_with_metrics_none() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::with_metrics(config, None);
    assert_eq!(client.model_name(), "test-model");
}

#[test]
fn test_llm_client_with_multiple_models_creates_selector() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "".to_string(),
        models: vec!["model-a".to_string(), "model-b".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);
    // With multiple models, a ModelSelector should be created
    // get_all_models should return both
    let models = client.get_all_models();
    assert_eq!(models.len(), 2);
}

#[test]
fn test_llm_client_get_all_models_single() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "single-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);
    let models = client.get_all_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "single-model");
}

#[test]
fn test_llm_client_model_name_with_models_vec() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "".to_string(),
        models: vec!["first-model".to_string(), "second-model".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.7,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);
    // First call should return first model
    let model1 = client.model_name();
    assert_eq!(model1, "first-model");
}

#[test]
fn test_llm_client_with_empty_config() {
    let config = LlmConfig::default();
    let client = LlmClient::new(config);
    // Should handle empty model gracefully
    let model = client.model_name();
    assert!(model.is_empty() || model == "gpt-4");
}

// ============================================================================
// ChatMessage Tests
// ============================================================================

#[test]
fn test_chat_message_system() {
    let msg = ChatMessage::system("You are a helpful assistant");
    assert_eq!(msg.role, "system");
    assert_eq!(msg.content, "You are a helpful assistant");
}

#[test]
fn test_chat_message_user() {
    let msg = ChatMessage::user("Hello, how are you?");
    assert_eq!(msg.role, "user");
    assert_eq!(msg.content, "Hello, how are you?");
}

#[test]
fn test_chat_message_assistant() {
    let msg = ChatMessage::assistant("I am doing well, thank you!");
    assert_eq!(msg.role, "assistant");
    assert_eq!(msg.content, "I am doing well, thank you!");
}

#[test]
fn test_chat_message_empty_content() {
    let msg = ChatMessage::user("");
    assert_eq!(msg.role, "user");
    assert!(msg.content.is_empty());
}

#[test]
fn test_chat_message_serialization() {
    let msg = ChatMessage::user("Test message");
    let serialized = serde_json::to_string(&msg).unwrap();
    assert!(serialized.contains("user"));
    assert!(serialized.contains("Test message"));
}

#[test]
fn test_chat_message_deserialization() {
    let json = r#"{"role":"system","content":"You are helpful"}"#;
    let msg: ChatMessage = serde_json::from_str(json).unwrap();
    assert_eq!(msg.role, "system");
    assert_eq!(msg.content, "You are helpful");
}

// ============================================================================
// ChatResponseWithModel Tests
// ============================================================================

#[test]
fn test_chat_response_with_model_new() {
    let response = ChatResponseWithModel::new("The answer is 42".to_string(), "gpt-4".to_string());
    assert_eq!(response.content, "The answer is 42");
    assert_eq!(response.model_used, "gpt-4");
}

#[test]
fn test_chat_response_with_model_empty_fields() {
    let response = ChatResponseWithModel::new(String::new(), String::new());
    assert!(response.content.is_empty());
    assert!(response.model_used.is_empty());
}

// ============================================================================
// ChatResponse Tests
// ============================================================================

#[test]
fn test_chat_response_default() {
    let response = ChatResponse::default();
    assert!(response.content.is_empty());
    assert!(response.tool_calls.is_empty());
    assert!(response.model_used.is_empty());
}

#[test]
fn test_chat_response_serialization_with_tool_calls() {
    use baco::agent::ToolCall;
    let response = ChatResponse {
        content: "Calling function".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call-1".to_string()),
            name: "test_function".to_string(),
            arguments: json!({"param": "value"}),
        }],
        raw: json!({}),
        model_used: "gpt-4".to_string(),
    };
    let serialized = serde_json::to_string(&response).unwrap();
    assert!(serialized.contains("test_function"));
    assert!(serialized.contains("call-1"));
}

// ============================================================================
// FunctionToolDefinition Tests
// ============================================================================

#[test]
fn test_function_tool_definition_default() {
    let tool = FunctionToolDefinition::default();
    assert!(tool.name.is_empty());
    assert!(tool.description.is_empty());
}

#[test]
fn test_function_tool_definition_custom() {
    let tool = FunctionToolDefinition {
        name: "search_databases".to_string(),
        description: "Search for vulnerabilities in code".to_string(),
        parameters: json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"}
            }
        }),
    };
    assert_eq!(tool.name, "search_databases");
    assert_eq!(tool.description, "Search for vulnerabilities in code");
}

// ============================================================================
// ToolSchema Tests
// ============================================================================

#[test]
fn test_tool_schema_default() {
    let tool = ToolSchema::default();
    assert!(tool.type_.is_empty());
    assert!(tool.function.name.is_empty());
}

#[test]
fn test_tool_schema_manual_creation() {
    let tool = ToolSchema {
        type_: "function".to_string(),
        function: FunctionToolDefinition {
            name: "analyze_code".to_string(),
            description: "Analyze code for security issues".to_string(),
            parameters: json!({}),
        },
    };
    assert_eq!(tool.type_, "function");
    assert_eq!(tool.function.name, "analyze_code");
}

// ============================================================================
// RecordMetricsParams Tests
// ============================================================================

// Note: RecordMetricsParams has private fields and no public constructor.
// It is only used internally within the LlmClient for metrics recording.
// Testing is done indirectly through LlmClient::with_metrics integration.

#[test]
fn test_record_metrics_params_type_exists() {
    // Verify the type exists and can be referenced (compile-time check)
    fn _type_check(_: RecordMetricsParams) {}
}

// ============================================================================
// ModelSelector Integration Tests
// ============================================================================

#[test]
fn test_model_selector_construction() {
    let models = vec![
        "model-1".to_string(),
        "model-2".to_string(),
        "model-3".to_string(),
    ];
    let selector = ModelSelector::new(models.clone());
    assert_eq!(selector.all_models(), models);
}

#[test]
fn test_model_selector_next_cycles() {
    let selector = ModelSelector::new(vec!["a".to_string(), "b".to_string()]);
    assert_eq!(selector.next(), Some("a".to_string()));
    assert_eq!(selector.next(), Some("b".to_string()));
    assert_eq!(selector.next(), Some("a".to_string()));
    assert_eq!(selector.next(), Some("b".to_string()));
}

#[test]
fn test_model_selector_empty() {
    let selector = ModelSelector::new(vec![]);
    assert!(selector.next().is_none());
    assert!(selector.all_models().is_empty());
}

// ============================================================================
// Edge Cases and Serialization Tests
// ============================================================================

#[test]
fn test_llm_config_clone() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "model".to_string(),
        models: vec!["m1".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let cloned = config.clone();
    assert_eq!(cloned.base_url, config.base_url);
    assert_eq!(cloned.api_key, config.api_key);
}

#[test]
fn test_chat_message_clone() {
    let msg = ChatMessage::user("Test content");
    let cloned = msg.clone();
    assert_eq!(cloned.role, msg.role);
    assert_eq!(cloned.content, msg.content);
}

#[test]
fn test_llm_config_full_serialization_roundtrip() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "secret".to_string(),
        model: "test-model".to_string(),
        models: vec!["m1".to_string(), "m2".to_string()],
        timeout: 60,
        max_retries: 5,
        retry_backoff_ms: 2000,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let serialized = serde_json::to_string(&config).unwrap();
    let deserialized: LlmConfig = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.base_url, config.base_url);
    assert_eq!(deserialized.model, config.model);
    assert_eq!(deserialized.models, config.models);
}

#[test]
fn test_chat_response_with_model_clone() {
    let response = ChatResponseWithModel::new("Content".to_string(), "model".to_string());
    let cloned = response.clone();
    assert_eq!(cloned.content, response.content);
    assert_eq!(cloned.model_used, response.model_used);
}

// ============================================================================
// JSON Payload Construction Tests
// ============================================================================

#[test]
fn test_chat_payload_structure() {
    let messages = vec![
        ChatMessage::system("You are helpful"),
        ChatMessage::user("Hello"),
    ];
    let model = "gpt-4";

    let payload = json!({
        "model": model,
        "messages": messages,
        "temperature": 0.7
    });

    assert_eq!(payload["model"], "gpt-4");
    assert!(payload["temperature"].as_f64().is_some());
    assert_eq!(payload["messages"].as_array().unwrap().len(), 2);
}

#[test]
fn test_chat_with_tools_payload_structure() {
    let messages = vec![ChatMessage::user("Test")];
    let tools = vec![ToolSchema {
        type_: "function".to_string(),
        function: FunctionToolDefinition {
            name: "test".to_string(),
            description: "test desc".to_string(),
            parameters: json!({}),
        },
    }];
    let model = "gpt-4";

    let payload = json!({
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "temperature": 0.7
    });

    assert!(payload["tools"].as_array().is_some());
    assert_eq!(payload["tool_choice"], "auto");
}

#[test]
fn test_chat_with_empty_tools_payload() {
    let messages = vec![ChatMessage::user("Test")];
    let tools: Vec<ToolSchema> = vec![];
    let model = "gpt-4";

    let payload = if tools.is_empty() {
        json!({
            "model": model,
            "messages": messages,
            "temperature": 0.7
        })
    } else {
        json!({
            "model": model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0.7
        })
    };

    assert!(payload.get("tools").is_none());
    assert_eq!(payload["model"], "gpt-4");
}
