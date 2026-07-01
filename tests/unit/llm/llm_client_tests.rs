//! Tests for LLM client functionality
//!
//! Covers: ModelSelector, LlmConfig, LlmClient, ChatMessage, error handling

use baco::llm::{ChatMessage, LlmClient, LlmConfig, ModelSelector};
use baco::llm_metrics::LlmMetricsTracker;

#[test]
fn test_model_selector_single_model() {
    let selector = ModelSelector::new(vec!["model-1".to_string()]);

    assert_eq!(selector.next(), Some("model-1".to_string()));
    assert_eq!(selector.next(), Some("model-1".to_string()));
    assert_eq!(selector.all_models(), vec!["model-1".to_string()]);
}

#[test]
fn test_model_selector_multiple_models_round_robin() {
    let selector = ModelSelector::new(vec![
        "model-a".to_string(),
        "model-b".to_string(),
        "model-c".to_string(),
    ]);

    assert_eq!(selector.next(), Some("model-a".to_string()));
    assert_eq!(selector.next(), Some("model-b".to_string()));
    assert_eq!(selector.next(), Some("model-c".to_string()));
    assert_eq!(selector.next(), Some("model-a".to_string())); // Wraps around
}

#[test]
fn test_model_selector_empty() {
    let selector = ModelSelector::new(vec![]);

    assert_eq!(selector.next(), None);
    let empty_vec: Vec<String> = vec![];
    assert_eq!(selector.all_models(), empty_vec);
}

#[test]
fn test_llm_config_get_models_single() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "gpt-4".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    assert_eq!(config.get_models(), vec!["gpt-4".to_string()]);
}

#[test]
fn test_llm_config_get_models_multiple() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "".to_string(),
        models: vec!["model-1".to_string(), "model-2".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    assert_eq!(
        config.get_models(),
        vec!["model-1".to_string(), "model-2".to_string()]
    );
}

#[test]
fn test_llm_config_get_models_empty() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    let empty_vec: Vec<String> = vec![];
    assert_eq!(config.get_models(), empty_vec);
}

#[test]
fn test_llm_config_default() {
    let config = LlmConfig::default();

    assert_eq!(config.base_url, "https://api.openai.com/v1");
    assert_eq!(config.model, "gpt-4");
    assert_eq!(config.timeout, 30);
    assert_eq!(config.max_retries, 3);
}

#[test]
fn test_llm_client_new_without_metrics() {
    let config = LlmConfig::default();
    let client = LlmClient::new(config.clone());

    assert_eq!(client.model_name(), config.model);
}

#[test]
fn test_llm_client_with_metrics() {
    let config = LlmConfig::default();
    let tracker = LlmMetricsTracker::new();
    let client = LlmClient::with_metrics(config, Some(tracker));

    assert!(!client.model_name().is_empty());
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
    };
    let client = LlmClient::new(config);

    assert_eq!(client.get_all_models(), vec!["single-model".to_string()]);
}

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
    let long_content = "A".repeat(10000);
    let msg = ChatMessage::user(&long_content);

    assert_eq!(msg.content.len(), 10000);
    assert_eq!(msg.role, "user");
}

#[test]
fn test_chat_message_unicode_content() {
    let msg = ChatMessage::user("Hello 你好 مرحبا");

    assert_eq!(msg.content, "Hello 你好 مرحبا");
}

// Note: RecordMetricsParams is internal, tested via integration tests

#[tokio::test]
async fn test_llm_client_model_selector_integration() {
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "".to_string(),
        models: vec!["model-1".to_string(), "model-2".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    let client = LlmClient::new(config);
    let models = client.get_all_models();

    assert_eq!(models.len(), 2);
    assert!(models.contains(&"model-1".to_string()));
    assert!(models.contains(&"model-2".to_string()));
}

#[tokio::test]
async fn test_llm_client_with_empty_config() {
    let config = LlmConfig {
        base_url: "".to_string(),
        api_key: "".to_string(),
        model: "".to_string(),
        models: vec![],
        timeout: 0,
        max_retries: 0,
        retry_backoff_ms: 0,
    };

    let client = LlmClient::new(config);

    // Should handle empty config gracefully
    assert!(client.model_name().is_empty());
}
