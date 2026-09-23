//! Unit tests for LLM config deserialization and phase configuration
//!
//! Tests cover:
//! 1. serde default for max_concurrent (Target 1)
//! 2. apply_retry_backoff with 429 and seconds (Target 2)
//! 3. get_current_model branches (Target 3)
//! 4. get_phase_config arms (Target 4)

use baco::config::ScannerConfig;
use baco::llm::{LlmClient, LlmConfig, apply_retry_backoff, phase_llm_config};

// ============================================================================
// Target 1: default_max_concurrent serde default
// ============================================================================

#[test]
fn test_deserialize_llm_config_without_max_concurrent_uses_default() {
    // Deserialize an LlmConfig from JSON without the max_concurrent field
    // The serde default fn fires, setting max_concurrent to 4
    let json = r#"{"base_url":"x","api_key":"k","model":"m","timeout":30,"max_retries":3,"retry_backoff_ms":1000}"#;
    let cfg: LlmConfig = serde_json::from_str(json).unwrap();

    assert_eq!(cfg.max_concurrent, 4);
}

#[test]
fn test_deserialize_llm_config_with_max_concurrent_uses_provided_value() {
    // Deserialize with explicit max_concurrent value
    let json = r#"{"base_url":"x","api_key":"k","model":"m","timeout":30,"max_retries":3,"retry_backoff_ms":1000,"max_concurrent":8}"#;
    let cfg: LlmConfig = serde_json::from_str(json).unwrap();

    assert_eq!(cfg.max_concurrent, 8);
}

// ============================================================================
// Target 2: apply_retry_backoff 429 with seconds
// ============================================================================

#[tokio::test]
async fn test_apply_retry_backoff_429_with_retry_after_seconds() {
    // Call with status=429, Some(0) for retry-after → secs * 1000 branch
    let mut retries = 0;
    apply_retry_backoff(100, 429, Some(0), &mut retries).await;

    // Assert: retries == 1 after the call, no panic
    assert_eq!(retries, 1);
}

#[tokio::test]
async fn test_apply_retry_backoff_429_with_nonzero_retry_after() {
    // Test with non-zero retry-after value
    let mut retries = 0;
    apply_retry_backoff(100, 429, Some(5), &mut retries).await;

    assert_eq!(retries, 1);
}

#[tokio::test]
async fn test_apply_retry_backoff_non_429_uses_backoff_delay() {
    // Test non-429 status uses exponential backoff
    let mut retries = 0;
    apply_retry_backoff(100, 500, None, &mut retries).await;

    assert_eq!(retries, 1);
}

// ============================================================================
// Target 3: get_current_model branches
// ============================================================================

#[test]
fn test_model_name_with_empty_model_and_single_model_in_vec() {
    // Line 349-350: LlmConfig { model: "", models: vec!["only".to_string()], .. }
    // → model_name() returns "only" (1 model, no selector, get_current_model → model empty → models.first() = Some)
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "".to_string(),
        models: vec!["only".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 4,
        pricing: Default::default(),
    };
    let client = LlmClient::new(config);

    assert_eq!(client.model_name(), "only");
}

#[test]
fn test_model_name_with_empty_model_and_empty_models_vec() {
    // Line 352: LlmConfig { model: "", models: vec![], .. }
    // → model_name() returns "" (0 models → models.first() = None → String::new())
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 4,
        pricing: Default::default(),
    };
    let client = LlmClient::new(config);

    assert_eq!(client.model_name(), "");
}

#[test]
fn test_model_name_with_nonempty_model_field() {
    // When model field is non-empty, it should be used
    let config = LlmConfig {
        base_url: "https://api.test.com/v1".to_string(),
        api_key: "key".to_string(),
        model: "my-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 4,
        pricing: Default::default(),
    };
    let client = LlmClient::new(config);

    assert_eq!(client.model_name(), "my-model");
}

// ============================================================================
// Target 4: get_phase_config arms
// ============================================================================

#[test]
fn test_phase_llm_config_threat_modeling_arm() {
    // Line 1326: "threat_modeling" arm - use a ScannerConfig with valid base_url + model
    let mut scanner_config = ScannerConfig::default();
    scanner_config.llm.base_url = "https://api.test.com/v1".to_string();
    scanner_config.llm.phases.threat_modeling.base_url =
        "https://threat-model.api.com/v1".to_string();
    scanner_config.llm.phases.threat_modeling.model = "threat-model".to_string();

    let result = phase_llm_config(&scanner_config, "threat_modeling", None);

    assert!(result.is_ok());
    let cfg = result.unwrap();
    assert_eq!(cfg.base_url, "https://threat-model.api.com/v1");
    assert_eq!(cfg.model, "threat-model");
}

#[test]
fn test_phase_llm_config_bogus_phase_default_arm() {
    // Line 1327: default `_` arm - bogus_phase returns LlmPhaseConfig::default()
    // then phase_llm_config errors (empty base_url in default → Err)
    let scanner_config = ScannerConfig::default();

    let result = phase_llm_config(&scanner_config, "bogus_phase", None);

    assert!(result.is_err());
}

#[test]
fn test_phase_llm_config_discovery_arm() {
    // Test discovery phase arm
    let mut scanner_config = ScannerConfig::default();
    scanner_config.llm.base_url = "https://api.test.com/v1".to_string();
    scanner_config.llm.phases.discovery.base_url = "https://discovery.api.com/v1".to_string();
    scanner_config.llm.phases.discovery.model = "discovery-model".to_string();

    let result = phase_llm_config(&scanner_config, "discovery", None);

    assert!(result.is_ok());
    let cfg = result.unwrap();
    assert_eq!(cfg.base_url, "https://discovery.api.com/v1");
}

#[test]
fn test_phase_llm_config_verification_arm() {
    // Test verification phase arm
    let mut scanner_config = ScannerConfig::default();
    scanner_config.llm.base_url = "https://api.test.com/v1".to_string();
    scanner_config.llm.phases.verification.base_url = "https://verification.api.com/v1".to_string();
    scanner_config.llm.phases.verification.model = "verification-model".to_string();

    let result = phase_llm_config(&scanner_config, "verification", None);

    assert!(result.is_ok());
}

#[test]
fn test_phase_llm_config_aggregation_arm() {
    // Test aggregation phase arm
    let mut scanner_config = ScannerConfig::default();
    scanner_config.llm.base_url = "https://api.test.com/v1".to_string();
    scanner_config.llm.phases.aggregation.base_url = "https://aggregation.api.com/v1".to_string();
    scanner_config.llm.phases.aggregation.model = "aggregation-model".to_string();

    let result = phase_llm_config(&scanner_config, "aggregation", None);

    assert!(result.is_ok());
}

#[test]
fn test_phase_llm_config_static_analysis_arm() {
    // Test static_analysis phase arm
    let mut scanner_config = ScannerConfig::default();
    scanner_config.llm.base_url = "https://api.test.com/v1".to_string();
    scanner_config.llm.phases.static_analysis.base_url = "https://static.api.com/v1".to_string();
    scanner_config.llm.phases.static_analysis.model = "static-model".to_string();

    let result = phase_llm_config(&scanner_config, "static_analysis", None);

    assert!(result.is_ok());
}

#[test]
fn test_phase_llm_config_security_agent_verification_arm() {
    // Test security_agent_verification phase arm
    let mut scanner_config = ScannerConfig::default();
    scanner_config.llm.base_url = "https://api.test.com/v1".to_string();
    scanner_config
        .llm
        .phases
        .security_agent_verification
        .base_url = "https://security.api.com/v1".to_string();
    scanner_config.llm.phases.security_agent_verification.model = "security-model".to_string();

    let result = phase_llm_config(&scanner_config, "security_agent_verification", None);

    assert!(result.is_ok());
}

#[test]
fn test_phase_llm_config_with_model_override() {
    // Test model_override parameter
    let mut scanner_config = ScannerConfig::default();
    scanner_config.llm.base_url = "https://api.test.com/v1".to_string();
    scanner_config.llm.phases.discovery.base_url = "https://discovery.api.com/v1".to_string();
    scanner_config.llm.phases.discovery.model = "original-model".to_string();

    let result = phase_llm_config(&scanner_config, "discovery", Some("override-model"));

    assert!(result.is_ok());
    let cfg = result.unwrap();
    assert_eq!(cfg.model, "override-model");
}
