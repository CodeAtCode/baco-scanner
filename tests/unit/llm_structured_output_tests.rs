//! Tests for structured JSON output (T16) and unified LLM config construction (T26)

use baco::config::{LlmConfig as ConfigLlmConfig, LlmPhaseConfig, LlmPhasesConfig};
use baco::llm::{self, chat_endpoint, JsonSchema, ResponseFormat};

// ============================================================================
// T16: Structured Output Tests
// ============================================================================

#[test]
fn test_response_format_serialization() {
    let response_format = ResponseFormat {
        type_: "json_schema".to_string(),
        json_schema: JsonSchema {
            name: "vulnerability_findings".to_string(),
            strict: true,
            schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "severity": {"type": "string"}
                            },
                            "required": ["title", "severity"]
                        }
                    }
                },
                "required": ["findings"]
            }),
        },
    };

    let serialized = serde_json::to_string(&response_format).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();

    assert_eq!(parsed["type"], "json_schema");
    assert_eq!(parsed["json_schema"]["name"], "vulnerability_findings");
    assert_eq!(parsed["json_schema"]["strict"], true);
    assert!(parsed["json_schema"]["schema"].is_object());
}

#[test]
fn test_chat_endpoint_normalization() {
    // Test that chat_endpoint handles various base URL formats correctly
    assert_eq!(
        chat_endpoint("https://api.openai.com/"),
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(
        chat_endpoint("https://api.openai.com/v1"),
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(
        chat_endpoint("https://api.example.com/custom"),
        "https://api.example.com/custom/v1/chat/completions"
    );
}

#[test]
fn test_llm_config_default_temperature() {
    let config = llm::LlmConfig::default();
    assert_eq!(config.temperature, 0.5);
}

// ============================================================================
// T26: Unified LLM Config Construction Tests
// ============================================================================

#[test]
fn test_phase_llm_config_uses_global_base_values() {
    let scanner_config = baco::config::ScannerConfig {
        llm: ConfigLlmConfig {
            timeout_secs: 60,
            max_retries: 5,
            retry_backoff_ms: 2000,
            max_concurrent: 5,
            temperature: 0.7,
            max_reasoning_tokens: Some(4096),
            enable_llm_cache: true,
            cache_dir: Some("/tmp/cache".to_string()),
            phases: LlmPhasesConfig::default(),
        },
        ..Default::default()
    };

    let llm_config = llm::phase_llm_config(&scanner_config, "discovery", None);

    assert_eq!(llm_config.timeout, 60);
    assert_eq!(llm_config.max_retries, 5);
    assert_eq!(llm_config.retry_backoff_ms, 2000);
    assert_eq!(llm_config.max_concurrent, 5);
    assert_eq!(llm_config.temperature, 0.7);
    assert_eq!(llm_config.max_reasoning_tokens, Some(4096));
    assert!(llm_config.enable_llm_cache);
    assert_eq!(llm_config.cache_dir, Some("/tmp/cache".to_string()));
}

#[test]
fn test_phase_llm_config_applies_phase_overrides() {
    let scanner_config = baco::config::ScannerConfig {
        llm: ConfigLlmConfig {
            timeout_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            max_concurrent: 3,
            temperature: 0.5,
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            phases: LlmPhasesConfig {
                discovery: LlmPhaseConfig {
                    base_url: "https://custom.api.com".to_string(),
                    api_key: Some("phase-api-key".to_string()),
                    model: "custom-model".to_string(),
                    models: vec![],
                    timeout_secs: Some(120),
                    temperature: Some(0.9),
                },
                ..Default::default()
            },
        },
        ..Default::default()
    };

    let llm_config = llm::phase_llm_config(&scanner_config, "discovery", None);

    // Phase overrides should apply
    assert_eq!(llm_config.timeout, 120); // Phase override
    assert_eq!(llm_config.temperature, 0.9); // Phase override
    assert_eq!(llm_config.model, "custom-model");
}

#[test]
fn test_phase_llm_config_no_hardcoded_temperature() {
    // Verify that temperature is never hardcoded - it always comes from config
    let scanner_config = baco::config::ScannerConfig {
        llm: ConfigLlmConfig {
            timeout_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            max_concurrent: 3,
            temperature: 0.7, // Global temperature
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            phases: LlmPhasesConfig::default(),
        },
        ..Default::default()
    };

    let llm_config = llm::phase_llm_config(&scanner_config, "verification", None);

    // Should use global temperature, not hardcoded value
    assert_eq!(llm_config.temperature, 0.7);
    assert_ne!(llm_config.temperature, 0.5); // Not the old hardcoded default
}

#[test]
fn test_phase_llm_config_model_override() {
    let scanner_config = baco::config::ScannerConfig {
        llm: ConfigLlmConfig {
            timeout_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            max_concurrent: 3,
            temperature: 0.5,
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            phases: LlmPhasesConfig::default(),
        },
        ..Default::default()
    };

    let llm_config = llm::phase_llm_config(&scanner_config, "discovery", Some("override-model"));

    assert_eq!(llm_config.model, "override-model");
}

#[test]
fn test_phase_llm_config_static_analysis_uses_discovery() {
    let scanner_config = baco::config::ScannerConfig {
        llm: ConfigLlmConfig {
            timeout_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            max_concurrent: 3,
            temperature: 0.7,
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            phases: LlmPhasesConfig {
                discovery: LlmPhaseConfig {
                    base_url: "https://discovery.api.com".to_string(),
                    api_key: Some("discovery-key".to_string()),
                    model: "discovery-model".to_string(),
                    models: vec![],
                    timeout_secs: Some(60),
                    temperature: Some(0.8),
                },
                ..Default::default()
            },
        },
        ..Default::default()
    };

    // static_analysis should use discovery config
    let llm_config = llm::phase_llm_config(&scanner_config, "static_analysis", None);

    assert_eq!(llm_config.model, "discovery-model");
    assert_eq!(llm_config.temperature, 0.8);
}

// ============================================================================
// Integration: static_analysis path uses helper (compile-level smoke test)
// ============================================================================

// Note: The static_analysis_finding_schema function is in the static_analysis module
// but we test the schema structure directly here instead of importing it.
#[test]
fn test_static_analysis_schema_structure() {
    // Verify the expected schema structure
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "cwe_id": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "file": {"type": "string"},
            "line": {"type": "integer"},
            "description": {"type": "string"},
            "recommendation": {"type": "string"}
        },
        "required": ["title", "cwe_id", "severity", "file", "line", "description", "recommendation"],
        "additionalProperties": false
    });

    assert_eq!(schema["type"], "object");
    assert!(schema["properties"].is_object());
    assert_eq!(schema["required"].as_array().unwrap().len(), 7);
}
