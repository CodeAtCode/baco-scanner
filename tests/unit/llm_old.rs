//! Comprehensive unit tests for LLM client module
//!
//! Tests cover:
//! - LLMConfig creation and validation
//! - ModelSelector round-robin behavior
//! - LlmClient construction and configuration
//! - ChatMessage builder patterns
//! - Function tool schema serialization
//! - ChatResponse parsing
//! - Error handling scenarios
//! - Metrics integration

use baco::llm::{
    ChatMessage, ChatResponse, ChatResponseWithModel, FunctionToolDefinition, LlmClient,
    LlmConfig, ModelSelector, ToolSchema,
};

// ============================================================================
// LlmConfig Tests
// ============================================================================

#[test]
fn test_llm_config_default() {
    let config = LlmConfig::default();
    assert_eq!(config.base_url, "https://api.openai.com/v1");
    assert_eq!(config.model, "gpt-4");
    assert_eq!(config.timeout, 30);
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.retry_backoff_ms, 1000);
    assert!(config.models.is_empty());
}

#[test]
fn test_llm_config_custom() {
    let config = LlmConfig {
        base_url: "https://custom.api.com/v1".to_string(),
        api_key: "secret-key".to_string(),
        model: "gpt-4-turbo".to_string(),
        models: vec![],
        timeout: 60,
        max_retries: 5,
        retry_backoff_ms: 2000,
    };

    assert_eq!(config.base_url, "https://custom.api.com/v1");
    assert_eq!(config.api_key, "secret-key");
    assert_eq!(config.model, "gpt-4-turbo");
    assert_eq!(config.timeout, 60);
    assert_eq!(config.max_retries, 5);
    assert_eq!(config.retry_backoff_ms, 2000);
}

#[test]
fn test_llm_config_get_models_single_model() {
    let config = LlmConfig {
        model: "gpt-4".to_string(),
        models: vec![],
        temperature: 0.5,
        ..Default::default()
    };

    let models = config.get_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "gpt-4");
}

#[test]
fn test_llm_config_get_models_multiple_models() {
    let config = LlmConfig {
        model: "".to_string(),
        models: vec!["gpt-4".to_string(), "gpt-3.5".to_string()],
        temperature: 0.5,
        ..Default::default()
    };

    let models = config.get_models();
    assert_eq!(models.len(), 2);
    assert_eq!(models[0], "gpt-4");
    assert_eq!(models[1], "gpt-3.5");
}

#[test]
fn test_llm_config_get_models_empty() {
    let config = LlmConfig {
        model: "".to_string(),
        models: vec![],
        temperature: 0.5,
        ..Default::default()
    };

    let models = config.get_models();
    assert!(models.is_empty());
}

#[test]
fn test_llm_config_models_priority() {
    // When both model and models are set, models should take priority
    let config = LlmConfig {
        model: "legacy-model".to_string(),
        models: vec!["new-model".to_string()],
        temperature: 0.5,
        ..Default::default()
    };

    let models = config.get_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "new-model");
}

// ============================================================================
// ModelSelector Tests
// ============================================================================

#[test]
fn test_model_selector_empty() {
    let selector = ModelSelector::new(vec![]);
    assert!(selector.next().is_none());
}

#[test]
fn test_model_selector_single_model() {
    let selector = ModelSelector::new(vec!["gpt-4".to_string()]);
    assert_eq!(selector.next(), Some("gpt-4".to_string()));
    assert_eq!(selector.next(), Some("gpt-4".to_string()));
}

#[test]
fn test_model_selector_round_robin() {
    let selector = ModelSelector::new(vec![
        "model-a".to_string(),
        "model-b".to_string(),
        "model-c".to_string(),
    ]);

    // Should cycle through models in order
    assert_eq!(selector.next(), Some("model-a".to_string()));
    assert_eq!(selector.next(), Some("model-b".to_string()));
    assert_eq!(selector.next(), Some("model-c".to_string()));
    assert_eq!(selector.next(), Some("model-a".to_string()));
    assert_eq!(selector.next(), Some("model-b".to_string()));
}

#[test]
fn test_model_selector_all_models() {
    let selector = ModelSelector::new(vec![
        "model-1".to_string(),
        "model-2".to_string(),
    ]);

    let all = selector.all_models();
    assert_eq!(all.len(), 2);
    assert_eq!(all, vec!["model-1".to_string(), "model-2".to_string()]);
}

#[test]
fn test_model_selector_thread_safe() {
    use std::sync::Arc;
    use std::thread;

    let selector = Arc::new(ModelSelector::new(vec![
        "model-a".to_string(),
        "model-b".to_string(),
    ]));

    let mut handles = vec![];

    // Spawn multiple threads calling next()
    for _ in 0..10 {
        let selector_clone = Arc::clone(&selector);
        handles.push(thread::spawn(move || {
            selector_clone.next()
        }));
    }

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();

    // All results should be valid models
    for result in results {
        assert!(result.is_some());
        let model = result.unwrap();
        assert!(model == "model-a" || model == "model-b");
    }
}

// ============================================================================
// LlmClient Tests
// ============================================================================

#[test]
fn test_llm_client_new_single_model() {
    let config = LlmConfig {
        model: "test-model".to_string(),
        ..Default::default()
    };

    let client = LlmClient::new(config);
    assert_eq!(client.model_name(), "test-model");
}

#[test]
fn test_llm_client_new_multiple_models() {
    let config = LlmConfig {
        model: "".to_string(),
        models: vec!["model-a".to_string(), "model-b".to_string()],
        ..Default::default()
    };

    let client = LlmClient::new(config);
    // First call should return first model
    let model1 = client.model_name();
    let model2 = client.model_name();
    // Due to round-robin, they might be different
    assert!(!model1.is_empty());
    assert!(!model2.is_empty());
}

#[test]
fn test_llm_client_with_metrics() {
    let config = LlmConfig {
        model: "test-model".to_string(),
        ..Default::default()
    };

    let client = LlmClient::with_metrics(config, None);
    assert_eq!(client.model_name(), "test-model");
}

#[test]
fn test_llm_client_get_all_models_single() {
    let config = LlmConfig {
        model: "gpt-4".to_string(),
        ..Default::default()
    };

    let client = LlmClient::new(config);
    let models = client.get_all_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "gpt-4");
}

#[test]
fn test_llm_client_get_all_models_multiple() {
    let config = LlmConfig {
        model: "".to_string(),
        models: vec!["gpt-4".to_string(), "gpt-3.5".to_string()],
        temperature: 0.5,
        ..Default::default()
    };

    let client = LlmClient::new(config);
    let models = client.get_all_models();
    assert_eq!(models.len(), 2);
}

#[test]
fn test_llm_client_empty_model() {
    let config = LlmConfig {
        model: "".to_string(),
        models: vec![],
        temperature: 0.5,
        ..Default::default()
    };

    let client = LlmClient::new(config);
    assert_eq!(client.model_name(), "");
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
    assert_eq!(msg.content, "");
}

#[test]
fn test_chat_message_very_long_content() {
    let long_text = "A".repeat(10000);
    let msg = ChatMessage::user(&long_text);
    assert_eq!(msg.content.len(), 10000);
}

#[test]
fn test_chat_message_special_characters() {
    let msg = ChatMessage::user("Hello! @#$%^&*()");
    assert!(msg.content.contains("@#$%^&*()"));
}

#[test]
fn test_chat_message_unicode() {
    let msg = ChatMessage::user("你好，世界！🌍");
    assert_eq!(msg.content, "你好，世界！🌍");
}

// ============================================================================
// FunctionToolDefinition Tests
// ============================================================================

#[test]
fn test_function_tool_definition_default() {
    let tool = FunctionToolDefinition::default();
    assert!(tool.name.is_empty());
    assert!(tool.description.is_empty());
    assert!(tool.parameters.is_null());
}

#[test]
fn test_function_tool_definition_custom() {
    let params = serde_json::json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"}
        }
    });

    let tool = FunctionToolDefinition {
        name: "get_weather".to_string(),
        description: "Get weather information".to_string(),
        parameters: params,
    };

    assert_eq!(tool.name, "get_weather");
    assert_eq!(tool.description, "Get weather information");
    assert!(tool.parameters.is_object());
}

#[test]
fn test_function_tool_definition_serialization() {
    let tool = FunctionToolDefinition {
        name: "test_tool".to_string(),
        description: "A test tool".to_string(),
        parameters: serde_json::json!({"key": "value"}),
    };

    let serialized = serde_json::to_string(&tool).unwrap();
    let deserialized: FunctionToolDefinition = serde_json::from_str(&serialized).unwrap();

    assert_eq!(tool.name, deserialized.name);
    assert_eq!(tool.description, deserialized.description);
    assert_eq!(tool.parameters, deserialized.parameters);
}

// ============================================================================
// ToolSchema Tests
// ============================================================================

#[test]
fn test_tool_schema_default() {
    let tool = ToolSchema::default();
    assert_eq!(tool.type_, "function");
    assert!(tool.function.name.is_empty());
}

#[test]
fn test_tool_schema_creation() {
    let function = FunctionToolDefinition {
        name: "search".to_string(),
        description: "Search the codebase".to_string(),
        parameters: serde_json::json!({}),
    };

    let tool = ToolSchema {
        type_: "function".to_string(),
        function,
    };

    assert_eq!(tool.type_, "function");
    assert_eq!(tool.function.name, "search");
}

#[test]
fn test_tool_schema_serialization() {
    let tool = ToolSchema {
        type_: "function".to_string(),
        function: FunctionToolDefinition {
            name: "test".to_string(),
            description: "Test".to_string(),
            parameters: serde_json::json!({}),
        },
    };

    let serialized = serde_json::to_string(&tool).unwrap();
    assert!(serialized.contains("function"));
    assert!(serialized.contains("test"));
}

// ============================================================================
// ChatResponse Tests
// ============================================================================

#[test]
fn test_chat_response_default() {
    let response = ChatResponse::default();
    assert!(response.content.is_empty());
    assert!(response.tool_calls.is_empty());
    assert!(response.raw.is_null());
    assert!(response.model_used.is_empty());
}

#[test]
fn test_chat_response_with_content() {
    let response = ChatResponse {
        content: "Hello, world!".to_string(),
        tool_calls: vec![],
        raw: serde_json::json!({}),
        model_used: "gpt-4".to_string(),
    };

    assert_eq!(response.content, "Hello, world!");
    assert_eq!(response.model_used, "gpt-4");
}

#[test]
fn test_chat_response_with_tool_calls() {
    use baco::agent::ToolCall;

    let tool_call = ToolCall {
        id: Some("call_123".to_string()),
        name: "search".to_string(),
        arguments: serde_json::json!({"query": "test"}),
    };

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![tool_call],
        raw: serde_json::json!({}),
        model_used: "gpt-4".to_string(),
    };

    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "search");
}

// ============================================================================
// ChatResponseWithModel Tests
// ============================================================================

#[test]
fn test_chat_response_with_model_new() {
    let response = ChatResponseWithModel::new("content".to_string(), "gpt-4".to_string());
    assert_eq!(response.content, "content");
    assert_eq!(response.model_used, "gpt-4");
}

#[test]
fn test_chat_response_with_model_empty() {
    let response = ChatResponseWithModel::new("".to_string(), "".to_string());
    assert!(response.content.is_empty());
    assert!(response.model_used.is_empty());
}

// ============================================================================
// Serialization/Deserialization Tests
// ============================================================================

#[test]
fn test_llm_config_serialization() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "model".to_string(),
        models: vec!["m1".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    let serialized = serde_json::to_string(&config).unwrap();
    let deserialized: LlmConfig = serde_json::from_str(&serialized).unwrap();

    assert_eq!(config.base_url, deserialized.base_url);
    assert_eq!(config.model, deserialized.model);
    assert_eq!(config.timeout, deserialized.timeout);
}

#[test]
fn test_chat_message_serialization() {
    let msg = ChatMessage::user("test content");

    let serialized = serde_json::to_string(&msg).unwrap();
    let deserialized: ChatMessage = serde_json::from_str(&serialized).unwrap();

    assert_eq!(msg.role, deserialized.role);
    assert_eq!(msg.content, deserialized.content);
}

// ============================================================================
// Edge Cases and Error Scenarios
// ============================================================================

#[test]
fn test_config_with_very_long_url() {
    let config = LlmConfig {
        base_url: "https://very-long-subdomain.example.com/api/v1/endpoint".to_string(),
        api_key: "key".to_string(),
        model: "model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    assert!(config.base_url.len() > 50);
}

#[test]
fn test_config_with_zero_timeout() {
    let config = LlmConfig {
        timeout: 0,
        ..Default::default()
    };

    assert_eq!(config.timeout, 0);
}

#[test]
fn test_config_with_high_retry_count() {
    let config = LlmConfig {
        max_retries: 100,
        retry_backoff_ms: 5000,
        ..Default::default()
    };

    assert_eq!(config.max_retries, 100);
    assert_eq!(config.retry_backoff_ms, 5000);
}

#[test]
fn test_model_selector_many_models() {
    let models: Vec<String> = (0..100).map(|i| format!("model-{}", i)).collect();
    let selector = ModelSelector::new(models);

    // Should be able to call next() many times without panic
    for i in 0..1000 {
        let model = selector.next().unwrap();
        assert!(model.starts_with("model-"));
    }
}

#[test]
fn test_chat_message_newline_content() {
    let msg = ChatMessage::user("Line 1\nLine 2\nLine 3");
    assert!(msg.content.contains('\n'));
    assert_eq!(msg.content.lines().count(), 3);
}

#[test]
fn test_chat_message_tab_content() {
    let msg = ChatMessage::user("Col1\tCol2\tCol3");
    assert!(msg.content.contains('\t'));
}

// ============================================================================
// Integration-style Tests (without actual API calls)
// ============================================================================

#[test]
fn test_complete_message_flow() {
    // Create a typical conversation flow
    let messages = vec![
        ChatMessage::system("You are a helpful coding assistant"),
        ChatMessage::user("How do I write a loop in Rust?"),
        ChatMessage::assistant("You can write a for loop like this: for i in 0..10 { ... }"),
        ChatMessage::user("Thanks!"),
    ];

    assert_eq!(messages.len(), 4);
    assert_eq!(messages[0].role, "system");
    assert_eq!(messages[1].role, "user");
    assert_eq!(messages[2].role, "assistant");
    assert_eq!(messages[3].role, "user");
}

#[test]
fn test_tool_definition_complete_schema() {
    let tool = ToolSchema {
        type_: "function".to_string(),
        function: FunctionToolDefinition {
            name: "analyze_code".to_string(),
            description: "Analyze code for security vulnerabilities".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Code to analyze"},
                    "language": {"type": "string", "description": "Programming language"}
                },
                "required": ["code"]
            }),
        },
    };

    let serialized = serde_json::to_string_pretty(&tool).unwrap();
    assert!(serialized.contains("analyze_code"));
    assert!(serialized.contains("security"));
    assert!(serialized.contains("code"));
}
