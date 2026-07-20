//! Integration tests for the MoE per-CWE router pipeline
//!
//! Tests that verify the router works correctly in an end-to-end scenario.

use baco::router::{CweRouter, PromptSpec, RouterConfig};
use std::collections::HashMap;

/// Test that the router correctly routes CWE-79 findings to the specialized prompt
#[test]
fn test_moe_pipeline_cwe_79_routing() {
    // Build a router with CWE-79 override
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // Route a finding with CWE-79
    let spec = router.route(&Some("79".to_string()), "javascript");

    // Assert: returned PromptSpec has the specialized template
    assert_eq!(spec.prompt_template, "xss_specialized");
}

/// Test that unknown CWEs fall back to the default prompt
#[test]
fn test_moe_pipeline_unknown_cwe_fallback() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // Route a finding with unknown CWE
    let spec = router.route(&Some("999".to_string()), "javascript");

    // Assert: falls back to default_prompt
    assert_eq!(spec.prompt_template, "llm_static_analysis");
}

/// Test language-based routing when no CWE match exists
#[test]
fn test_moe_pipeline_language_routing() {
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "rust".to_string(),
        PromptSpec {
            prompt_template: "rust_specialized".to_string(),
            model_override: Some("gpt-4".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // Route a finding with no CWE but Rust language
    let spec = router.route(&None, "rust");

    assert_eq!(spec.prompt_template, "rust_specialized");
    assert_eq!(spec.model_override, Some("gpt-4".to_string()));
}

/// Test that CWE routing takes priority over language routing
#[test]
fn test_moe_pipeline_cwe_priority() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "89".to_string(),
        PromptSpec {
            prompt_template: "sqli_specialized".to_string(),
            model_override: None,
        },
    );

    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "rust".to_string(),
        PromptSpec {
            prompt_template: "rust_specialized".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // CWE-89 should match even for Rust language
    let spec = router.route(&Some("89".to_string()), "rust");
    assert_eq!(spec.prompt_template, "sqli_specialized");
}

/// Test full pipeline with multiple CWEs
#[test]
fn test_moe_pipeline_multiple_cwes() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: None,
        },
    );
    cwe_overrides.insert(
        "89".to_string(),
        PromptSpec {
            prompt_template: "sqli_specialized".to_string(),
            model_override: None,
        },
    );
    cwe_overrides.insert(
        "120".to_string(),
        PromptSpec {
            prompt_template: "buffer_overflow_specialized".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // Test each CWE routes correctly
    let spec_79 = router.route(&Some("79".to_string()), "c");
    assert_eq!(spec_79.prompt_template, "xss_specialized");

    let spec_89 = router.route(&Some("89".to_string()), "rust");
    assert_eq!(spec_89.prompt_template, "sqli_specialized");

    let spec_120 = router.route(&Some("120".to_string()), "c");
    assert_eq!(spec_120.prompt_template, "buffer_overflow_specialized");

    // Unknown CWE falls back to default
    let spec_unknown = router.route(&Some("555".to_string()), "python");
    assert_eq!(spec_unknown.prompt_template, "llm_static_analysis");
}
