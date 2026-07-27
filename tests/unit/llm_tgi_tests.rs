//! Unit tests for TGI (Text Generation Inference) client
//!
//! Tests cover:
//! 1. TgiClient construction (new, with_options)
//! 2. TgiConfig validation and defaults
//! 3. CompletionOptions creation and usage
//! 4. Edge cases: empty input, disabled config, missing fields
//! 5. All public API functionality

use baco::config::TgiConfig;
use baco::llm::{CompletionOptions, TgiClient};

// ============================================================================
// TgiConfig Tests
// ============================================================================

#[test]
fn test_tgi_config_default_disabled() {
    let config = TgiConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.endpoint, "http://localhost:8080");
    assert_eq!(config.max_new_tokens, 2048);
    assert_eq!(config.temperature, 0.1);
    assert_eq!(config.timeout_secs, 120);
    assert!(config.do_sample);
}

#[test]
fn test_tgi_config_custom_enabled() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://tgi.example.com:8080".to_string(),
        model: "r2vul-model".to_string(),
        max_new_tokens: 512,
        temperature: 0.7,
        timeout_secs: 60,
        do_sample: true,
    };
    assert!(config.enabled);
    assert_eq!(config.endpoint, "http://tgi.example.com:8080");
    assert_eq!(config.model, "r2vul-model");
    assert_eq!(config.max_new_tokens, 512);
    assert_eq!(config.temperature, 0.7);
}

#[test]
fn test_tgi_config_empty_model() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: String::new(),
        ..Default::default()
    };
    assert!(config.model.is_empty());
}

#[test]
fn test_tgi_config_zero_timeout() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test".to_string(),
        timeout_secs: 0,
        ..Default::default()
    };
    assert_eq!(config.timeout_secs, 0);
}

#[test]
fn test_tgi_config_clone() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test-model".to_string(),
        max_new_tokens: 1024,
        temperature: 0.5,
        timeout_secs: 30,
        do_sample: true,
    };
    let cloned = config.clone();
    assert_eq!(cloned.enabled, config.enabled);
    assert_eq!(cloned.endpoint, config.endpoint);
    assert_eq!(cloned.model, config.model);
}

// ============================================================================
// TgiClient Construction Tests
// ============================================================================

#[test]
fn test_tgi_client_new_disabled() {
    let config = TgiConfig::default();
    let result = TgiClient::new(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not enabled"));
}

#[test]
fn test_tgi_client_new_missing_endpoint() {
    let config = TgiConfig {
        enabled: true,
        endpoint: String::new(),
        model: "test-model".to_string(),
        ..Default::default()
    };
    let result = TgiClient::new(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("endpoint"));
}

#[test]
fn test_tgi_client_new_missing_model() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: String::new(),
        ..Default::default()
    };
    let result = TgiClient::new(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("model"));
}

#[test]
fn test_tgi_client_new_success() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test-model".to_string(),
        max_new_tokens: 1024,
        temperature: 0.5,
        timeout_secs: 30,
        do_sample: true,
    };
    let result = TgiClient::new(&config);
    assert!(result.is_ok());
}

#[test]
fn test_tgi_client_with_options_default() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test-model".to_string(),
        ..Default::default()
    };
    let options = CompletionOptions::default();
    let result = TgiClient::with_options(&config, &options);
    assert!(result.is_ok());
}

#[test]
fn test_tgi_client_with_options_custom_tokens() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test-model".to_string(),
        max_new_tokens: 2048,
        ..Default::default()
    };
    let options = CompletionOptions {
        max_new_tokens: Some(512),
        temperature: None,
        stop: vec![],
    };
    let result = TgiClient::with_options(&config, &options);
    assert!(result.is_ok());
}

#[test]
fn test_tgi_client_with_options_custom_temperature() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test-model".to_string(),
        temperature: 0.1,
        ..Default::default()
    };
    let options = CompletionOptions {
        max_new_tokens: None,
        temperature: Some(0.9),
        stop: vec![],
    };
    let result = TgiClient::with_options(&config, &options);
    assert!(result.is_ok());
}

#[test]
fn test_tgi_client_with_options_disabled_config() {
    let config = TgiConfig::default();
    let options = CompletionOptions {
        max_new_tokens: Some(512),
        temperature: Some(0.8),
        stop: vec![],
    };
    let result = TgiClient::with_options(&config, &options);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not enabled"));
}

#[test]
fn test_tgi_client_clone() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test-model".to_string(),
        max_new_tokens: 1024,
        temperature: 0.5,
        timeout_secs: 30,
        do_sample: true,
    };
    let client = TgiClient::new(&config).unwrap();
    let cloned = client.clone();
    // Clone should succeed and produce an equivalent client
    assert!(cloned.is_available() == client.is_available());
}

// ============================================================================
// CompletionOptions Tests
// ============================================================================

#[test]
fn test_completion_options_default() {
    let options = CompletionOptions::default();
    assert!(options.max_new_tokens.is_none());
    assert!(options.temperature.is_none());
    assert!(options.stop.is_empty());
}

#[test]
fn test_completion_options_custom() {
    let options = CompletionOptions {
        max_new_tokens: Some(512),
        temperature: Some(0.8),
        stop: vec!["\n".to_string(), "END".to_string()],
    };
    assert_eq!(options.max_new_tokens, Some(512));
    assert_eq!(options.temperature, Some(0.8));
    assert_eq!(options.stop.len(), 2);
}

#[test]
fn test_completion_options_only_stop() {
    let options = CompletionOptions {
        max_new_tokens: None,
        temperature: None,
        stop: vec!["STOP".to_string()],
    };
    assert!(options.max_new_tokens.is_none());
    assert!(options.temperature.is_none());
    assert_eq!(options.stop.len(), 1);
}

#[test]
fn test_completion_options_clone() {
    let options = CompletionOptions {
        max_new_tokens: Some(1024),
        temperature: Some(0.7),
        stop: vec!["\n".to_string()],
    };
    let cloned = options.clone();
    assert_eq!(cloned.max_new_tokens, options.max_new_tokens);
    assert_eq!(cloned.temperature, options.temperature);
    assert_eq!(cloned.stop, options.stop);
}

#[test]
fn test_completion_options_empty_stop() {
    let options = CompletionOptions {
        max_new_tokens: Some(512),
        temperature: Some(0.5),
        stop: vec![],
    };
    assert!(options.stop.is_empty());
}

// ============================================================================
// Client Behavior Tests
// ============================================================================

#[test]
fn test_client_new_with_different_endpoints() {
    let endpoints = vec![
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "https://tgi.example.com",
        "http://localhost:3000/v1",
    ];

    for endpoint in endpoints {
        let config = TgiConfig {
            enabled: true,
            endpoint: endpoint.to_string(),
            model: "test".to_string(),
            ..Default::default()
        };
        let result = TgiClient::new(&config);
        assert!(result.is_ok(), "Failed for endpoint: {}", endpoint);
    }
}

#[test]
fn test_client_new_with_different_models() {
    let models = vec![
        "r2vul",
        "vulpo",
        "custom-model-name",
        "org/model-name",
        "model-with-dashes",
    ];

    for model in models {
        let config = TgiConfig {
            enabled: true,
            endpoint: "http://localhost:8080".to_string(),
            model: model.to_string(),
            ..Default::default()
        };
        let result = TgiClient::new(&config);
        assert!(result.is_ok(), "Failed for model: {}", model);
    }
}

#[test]
fn test_client_new_with_extreme_token_values() {
    // Test with very large max_new_tokens
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test".to_string(),
        max_new_tokens: usize::MAX,
        ..Default::default()
    };
    let result = TgiClient::new(&config);
    assert!(result.is_ok());

    // Test with zero max_new_tokens
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test".to_string(),
        max_new_tokens: 0,
        ..Default::default()
    };
    let result = TgiClient::new(&config);
    assert!(result.is_ok());
}

#[test]
fn test_client_new_with_extreme_temperature_values() {
    // Test with temperature 0.0 (greedy)
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test".to_string(),
        temperature: 0.0,
        ..Default::default()
    };
    let result = TgiClient::new(&config);
    assert!(result.is_ok());

    // Test with temperature 1.0 (maximum randomness)
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test".to_string(),
        temperature: 1.0,
        ..Default::default()
    };
    let result = TgiClient::new(&config);
    assert!(result.is_ok());

    // Test with temperature > 1.0 (unconstrained sampling)
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test".to_string(),
        temperature: 2.0,
        ..Default::default()
    };
    let result = TgiClient::new(&config);
    assert!(result.is_ok());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_tgi_config_with_whitespace_endpoint() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "   ".to_string(),
        model: "test".to_string(),
        ..Default::default()
    };
    // Whitespace-only endpoint should be accepted by client creation
    // (validation happens at request time)
    let result = TgiClient::new(&config);
    assert!(result.is_ok());
}

#[test]
fn test_completion_options_with_many_stop_sequences() {
    let options = CompletionOptions {
        max_new_tokens: Some(100),
        temperature: Some(0.5),
        stop: vec![
            "\n".to_string(),
            "END".to_string(),
            "STOP".to_string(),
            "###".to_string(),
            "<|endoftext|>".to_string(),
        ],
    };
    assert_eq!(options.stop.len(), 5);
}

#[test]
fn test_tgi_config_debug_display() {
    let config = TgiConfig::default();
    let debug_str = format!("{:?}", config);
    assert!(debug_str.contains("TgiConfig"));
}

#[test]
fn test_completion_options_debug_display() {
    let options = CompletionOptions::default();
    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("CompletionOptions"));
}

#[test]
fn test_tgi_client_debug_display() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test-model".to_string(),
        ..Default::default()
    };
    let client = TgiClient::new(&config).unwrap();
    let debug_str = format!("{:?}", client);
    assert!(debug_str.contains("TgiClient"));
}

// ============================================================================
// Integration-style Tests (without actual HTTP calls)
// ============================================================================

#[test]
fn test_complete_workflow_config_to_client() {
    // Simulate the workflow: config -> client -> options
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "r2vul".to_string(),
        max_new_tokens: 512,
        temperature: 0.3,
        timeout_secs: 60,
        do_sample: true,
    };

    // Create base client
    let base_client = TgiClient::new(&config).unwrap();

    // Create client with custom options
    let options = CompletionOptions {
        max_new_tokens: Some(256),
        temperature: Some(0.5),
        stop: vec!["\n\n".to_string()],
    };
    let custom_client = TgiClient::with_options(&config, &options).unwrap();

    // Both should be valid clients
    assert!(base_client.is_available() == custom_client.is_available());
}

#[test]
fn test_multiple_clients_same_config() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "test".to_string(),
        ..Default::default()
    };

    let client1 = TgiClient::new(&config).unwrap();
    let client2 = TgiClient::new(&config).unwrap();

    // Both clients should be equivalent
    assert!(client1.is_available() == client2.is_available());
}
