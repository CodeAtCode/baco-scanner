//! Integration-facing unit tests for llm_core_edge_tests coverage gaps.
//! Tests use only public crate API (baco::) and run without external services.

use baco::config::{LlmPhaseConfig, LlmPhasesConfig, ScannerConfig};
use baco::error::ScanError;
use baco::llm::{
    create_llm_client_with_metrics, phase_llm_config, AtomicModelSelector, ChatMessage,
    ChatResponseWithModel, LlmClient, LlmConfig,
};

// ============================================================================
// LlmConfig and phase_llm_config Tests
// ============================================================================

#[test]
fn test_phase_llm_config_missing_base_url_returns_error() {
    // When phase has no base_url, phase_llm_config returns ScanError::Config
    let config = ScannerConfig::default();
    let result = phase_llm_config(&config, "discovery", None);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, ScanError::Config { .. }));
    let display = format!("{}", err);
    assert!(display.contains("discovery"));
    assert!(display.contains("base_url"));
}

#[test]
fn test_phase_llm_config_empty_models_returns_error() {
    // When phase has base_url but no models, phase_llm_config returns ScanError::Config
    let config = ScannerConfig {
        llm: baco::config::LlmConfig {
            phases: LlmPhasesConfig {
                discovery: LlmPhaseConfig {
                    base_url: "http://test.com".to_string(),
                    api_key: Some("test-key".to_string()),
                    model: "".to_string(),
                    models: vec![],
                    temperature: None,
                    timeout_secs: None,
                    agent_flow: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let result = phase_llm_config(&config, "discovery", None);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, ScanError::Config { .. }));
    let display = format!("{}", err);
    assert!(display.contains("discovery"));
    assert!(display.contains("model"));
}

#[test]
fn test_phase_llm_config_valid_config_preserves_models_in_order() {
    // Valid config preserves model order for round-robin
    let config = ScannerConfig {
        llm: baco::config::LlmConfig {
            phases: LlmPhasesConfig {
                verification: LlmPhaseConfig {
                    base_url: "http://test.com".to_string(),
                    api_key: Some("test-key".to_string()),
                    model: "".to_string(),
                    models: vec![
                        "model-a".to_string(),
                        "model-b".to_string(),
                        "model-c".to_string(),
                    ],
                    temperature: None,
                    timeout_secs: None,
                    agent_flow: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let result = phase_llm_config(&config, "verification", None);
    assert!(result.is_ok());
    let llm_config = result.unwrap();

    let models = llm_config.get_models();
    assert_eq!(models.len(), 3);
    assert_eq!(models[0], "model-a");
    assert_eq!(models[1], "model-b");
    assert_eq!(models[2], "model-c");
}

#[test]
fn test_phase_llm_config_phase_override_beats_global() {
    // Phase-specific settings override global defaults
    let config = ScannerConfig {
        llm: baco::config::LlmConfig {
            timeout_secs: 60, // Global timeout
            temperature: 0.7, // Global temperature
            phases: LlmPhasesConfig {
                static_analysis: LlmPhaseConfig {
                    base_url: "http://phase-specific.com".to_string(),
                    api_key: Some("phase-key".to_string()),
                    model: "phase-model".to_string(),
                    models: vec![],
                    temperature: Some(0.3), // Phase override
                    timeout_secs: Some(30), // Phase override
                    agent_flow: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let result = phase_llm_config(&config, "static_analysis", None);
    assert!(result.is_ok());
    let llm_config = result.unwrap();

    assert_eq!(llm_config.timeout, 30); // Phase override, not global 60
    assert!((llm_config.temperature - 0.3).abs() < f32::EPSILON); // Phase override, not global 0.7
    assert_eq!(llm_config.base_url, "http://phase-specific.com");
}

#[test]
fn test_phase_llm_config_model_override_takes_precedence() {
    // model_override parameter takes precedence over configured models
    let config = ScannerConfig {
        llm: baco::config::LlmConfig {
            phases: LlmPhasesConfig {
                aggregation: LlmPhaseConfig {
                    base_url: "http://test.com".to_string(),
                    api_key: Some("test-key".to_string()),
                    model: "".to_string(),
                    models: vec!["configured-model".to_string()],
                    temperature: None,
                    timeout_secs: None,
                    agent_flow: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let result = phase_llm_config(&config, "aggregation", Some("override-model"));
    assert!(result.is_ok());
    let llm_config = result.unwrap();

    let models = llm_config.get_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "override-model");
}

// ============================================================================
// create_llm_client_with_metrics Tests
// ============================================================================

#[test]
fn test_create_llm_client_with_metrics_none_on_missing_api_key() {
    // Returns None when phase has no API key
    let config = ScannerConfig {
        llm: baco::config::LlmConfig {
            phases: LlmPhasesConfig {
                discovery: LlmPhaseConfig {
                    base_url: "http://test.com".to_string(),
                    api_key: None, // No API key
                    model: "test-model".to_string(),
                    models: vec![],
                    temperature: None,
                    timeout_secs: None,
                    agent_flow: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    // Create a minimal scanner for testing
    use baco::llm_metrics::LlmMetricsTracker;
    use baco::scanner::core::Scanner;

    let metrics = LlmMetricsTracker::new();
    let mut scanner = Scanner::new(config, std::path::PathBuf::from("/tmp"), false);
    scanner.metrics_tracker = metrics;

    let client = create_llm_client_with_metrics(&scanner, "discovery");
    assert!(client.is_none());
}

#[test]
fn test_create_llm_client_with_metrics_none_on_missing_base_url() {
    // Returns None when phase has no base_url
    let _config = ScannerConfig {
        llm: baco::config::LlmConfig {
            phases: LlmPhasesConfig {
                verification: LlmPhaseConfig {
                    base_url: "".to_string(), // No base_url
                    api_key: Some("test-key".to_string()),
                    model: "test-model".to_string(),
                    models: vec![],
                    temperature: None,
                    timeout_secs: None,
                    agent_flow: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    use baco::llm_metrics::LlmMetricsTracker;
    use baco::scanner::core::Scanner;

    let mut config = ScannerConfig::default();
    config.llm.phases.verification.base_url = "".to_string();
    config.llm.phases.verification.api_key = Some("test-key".to_string());
    config.llm.phases.verification.model = "test-model".to_string();

    let metrics = LlmMetricsTracker::new();
    let mut scanner = Scanner::new(config, std::path::PathBuf::from("/tmp"), false);
    scanner.metrics_tracker = metrics;

    let client = create_llm_client_with_metrics(&scanner, "verification");
    assert!(client.is_none());
}

#[test]
fn test_create_llm_client_with_metrics_none_on_empty_models() {
    // Returns None when phase has no models configured
    let _config = ScannerConfig {
        llm: baco::config::LlmConfig {
            phases: LlmPhasesConfig {
                aggregation: LlmPhaseConfig {
                    base_url: "http://test.com".to_string(),
                    api_key: Some("test-key".to_string()),
                    model: "".to_string(),
                    models: vec![], // No models
                    temperature: None,
                    timeout_secs: None,
                    agent_flow: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    use baco::llm_metrics::LlmMetricsTracker;
    use baco::scanner::core::Scanner;

    let mut config = ScannerConfig::default();
    config.llm.phases.aggregation.base_url = "http://test.com".to_string();
    config.llm.phases.aggregation.api_key = Some("test-key".to_string());
    config.llm.phases.aggregation.model = "".to_string();
    config.llm.phases.aggregation.models = vec![];

    let metrics = LlmMetricsTracker::new();
    let mut scanner = Scanner::new(config, std::path::PathBuf::from("/tmp"), false);
    scanner.metrics_tracker = metrics;

    let client = create_llm_client_with_metrics(&scanner, "aggregation");
    assert!(client.is_none());
}

#[test]
fn test_create_llm_client_with_metrics_some_on_valid_config() {
    // Returns Some(LlmClient) when phase has complete config
    let config = ScannerConfig {
        llm: baco::config::LlmConfig {
            phases: LlmPhasesConfig {
                security_agent_verification: LlmPhaseConfig {
                    base_url: "http://test.com".to_string(),
                    api_key: Some("test-key".to_string()),
                    model: "test-model".to_string(),
                    models: vec![],
                    temperature: None,
                    timeout_secs: None,
                    agent_flow: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    use baco::llm_metrics::LlmMetricsTracker;
    use baco::scanner::core::Scanner;

    let metrics = LlmMetricsTracker::new();
    let mut scanner = Scanner::new(config, std::path::PathBuf::from("/tmp"), false);
    scanner.metrics_tracker = metrics;

    let client = create_llm_client_with_metrics(&scanner, "security_agent_verification");
    assert!(client.is_some());
}

// ============================================================================
// LlmClient Model Selection Tests
// ============================================================================

#[test]
fn test_atomic_model_selector_round_robin() {
    // Round-robin selection cycles through models in order
    let selector = AtomicModelSelector::new(vec![
        "model-a".to_string(),
        "model-b".to_string(),
        "model-c".to_string(),
    ]);

    assert_eq!(selector.next(), "model-a");
    assert_eq!(selector.next(), "model-b");
    assert_eq!(selector.next(), "model-c");
    assert_eq!(selector.next(), "model-a"); // Wraps around
    assert_eq!(selector.next(), "model-b");
}

#[test]
fn test_atomic_model_selector_empty_returns_empty_string() {
    // Empty selector returns empty string
    let selector = AtomicModelSelector::new(vec![]);
    assert_eq!(selector.next(), "");
}

#[test]
fn test_atomic_model_selector_all_models_returns_copy() {
    // all_models returns a copy of the internal vector
    let selector = AtomicModelSelector::new(vec!["model-x".to_string(), "model-y".to_string()]);

    let models = selector.all_models();
    assert_eq!(models.len(), 2);
    assert_eq!(models[0], "model-x");
    assert_eq!(models[1], "model-y");
}

#[test]
fn test_llm_client_get_all_models_single_model() {
    // Single model config returns that model
    let config = LlmConfig::default();
    let config = LlmConfig {
        base_url: "http://test.com".to_string(),
        api_key: "test-key".to_string(),
        model: "single-model".to_string(),
        ..config
    };

    let client = LlmClient::new(config);
    let models = client.get_all_models();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0], "single-model");
}

#[test]
fn test_llm_client_model_name_uses_first_when_multiple() {
    // When multiple models configured, model_name returns first one initially
    let config = LlmConfig::default();
    let config = LlmConfig {
        base_url: "http://test.com".to_string(),
        api_key: "test-key".to_string(),
        model: "".to_string(),
        models: vec!["first".to_string(), "second".to_string()],
        ..config
    };

    let client = LlmClient::new(config);
    assert_eq!(client.model_name(), "first");
}

// ============================================================================
// LlmClient classify_retryable Tests
// ============================================================================

#[test]
fn test_classify_retryable_400_bad_request_no_retry() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(400, None);
    assert!(!should_retry);
    assert_eq!(retry_after, None);
}

#[test]
fn test_classify_retryable_401_auth_no_retry() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(401, None);
    assert!(!should_retry);
    assert_eq!(retry_after, None);
}

#[test]
fn test_classify_retryable_403_forbidden_no_retry() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(403, None);
    assert!(!should_retry);
    assert_eq!(retry_after, None);
}

#[test]
fn test_classify_retryable_408_timeout_retry() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(408, None);
    assert!(should_retry);
    assert_eq!(retry_after, None);
}

#[test]
fn test_classify_retryable_429_rate_limit_with_retry_after() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(429, Some(30));
    assert!(should_retry);
    assert_eq!(retry_after, Some(30));
}

#[test]
fn test_classify_retryable_429_rate_limit_without_retry_after() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(429, None);
    assert!(should_retry);
    assert_eq!(retry_after, None);
}

#[test]
fn test_classify_retryable_500_server_error_retry() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(500, None);
    assert!(should_retry);
    assert_eq!(retry_after, None);
}

#[test]
fn test_classify_retryable_503_unavailable_retry() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(503, None);
    assert!(should_retry);
    assert_eq!(retry_after, None);
}

#[test]
fn test_classify_retryable_200_success_no_retry() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(200, None);
    assert!(!should_retry);
    assert_eq!(retry_after, None);
}

#[test]
fn test_classify_retryable_404_not_found_no_retry() {
    let (should_retry, retry_after) = LlmClient::classify_retryable(404, None);
    assert!(!should_retry);
    assert_eq!(retry_after, None);
}

// ============================================================================
// ChatMessage Tests
// ============================================================================

#[test]
fn test_chat_message_system_constructor() {
    let msg = ChatMessage::system("You are a helpful assistant");
    assert_eq!(msg.role, "system");
    assert_eq!(msg.content, "You are a helpful assistant");
}

#[test]
fn test_chat_message_user_constructor() {
    let msg = ChatMessage::user("Hello, how can you help me?");
    assert_eq!(msg.role, "user");
    assert_eq!(msg.content, "Hello, how can you help me?");
}

#[test]
fn test_chat_message_assistant_constructor() {
    let msg = ChatMessage::assistant("I can help you with that.");
    assert_eq!(msg.role, "assistant");
    assert_eq!(msg.content, "I can help you with that.");
}

// ============================================================================
// ChatResponseWithModel Tests
// ============================================================================

#[test]
fn test_chat_response_with_model_new() {
    let response = ChatResponseWithModel::new("Test content".to_string(), "test-model".to_string());
    assert_eq!(response.content, "Test content");
    assert_eq!(response.model_used, "test-model");
}
