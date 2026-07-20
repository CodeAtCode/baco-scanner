//! Tests for the MoE per-CWE / per-language router

use baco::router::{CweRouter, PromptSpec, RouterConfig, RouterRegistry};
use std::collections::HashMap;

#[test]
fn test_route_by_cwe_79_returns_xss_spec() {
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
    let spec = router.route_by_cwe("79").unwrap();
    assert_eq!(spec.prompt_template, "xss_specialized");
}

#[test]
fn test_route_by_cwe_89_returns_sqli_spec() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "89".to_string(),
        PromptSpec {
            prompt_template: "sqli_specialized".to_string(),
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
    let spec = router.route_by_cwe("89").unwrap();
    assert_eq!(spec.prompt_template, "sqli_specialized");
}

#[test]
fn test_route_by_cwe_unknown_returns_none() {
    let config = RouterConfig::default();
    let router = CweRouter::from_config(&config);

    let spec = router.route_by_cwe("unknown");
    assert!(spec.is_none());
}

#[test]
fn test_route_by_language_c_returns_c_spec() {
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "c".to_string(),
        PromptSpec {
            prompt_template: "c_specialized".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };

    let router = CweRouter::from_config(&config);
    let spec = router.route_by_language("c").unwrap();
    assert_eq!(spec.prompt_template, "c_specialized");
}

#[test]
fn test_route_cwe_priority_over_language() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: None,
        },
    );

    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "c".to_string(),
        PromptSpec {
            prompt_template: "c_specialized".to_string(),
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

    // CWE match should take priority
    let spec = router.route(&Some("79".to_string()), "c");
    assert_eq!(spec.prompt_template, "xss_specialized");
}

#[test]
fn test_route_unknown_cwe_falls_back_to_default() {
    let config = RouterConfig {
        enabled: true,
        default_prompt: "custom_default".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // Unknown CWE with no language override should fall back to default
    let spec = router.route(&Some("999".to_string()), "unknown_lang");
    assert_eq!(spec.prompt_template, "custom_default");
}

#[test]
fn test_router_config_default() {
    let config = RouterConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.default_prompt, "llm_static_analysis");
    assert!(config.cwe_overrides.is_empty());
    assert!(config.language_overrides.is_empty());
}

#[test]
fn test_config_loads_from_toml() {
    // Test that RouterConfig can be deserialized from TOML
    let toml_str = r#"
enabled = true
default_prompt = "custom_prompt"
"#;

    let config: RouterConfig = toml::from_str(toml_str).unwrap();

    assert!(config.enabled);
    assert_eq!(config.default_prompt, "custom_prompt");
    assert!(config.cwe_overrides.is_empty());
    assert!(config.language_overrides.is_empty());
}

#[test]
fn test_router_registry_cwe_override() {
    let mut registry = RouterRegistry::new();

    let spec = PromptSpec {
        prompt_template: "test_template".to_string(),
        model_override: Some("custom-model".to_string()),
    };

    registry.add_cwe_override("120".to_string(), spec.clone());

    assert_eq!(registry.get_cwe("120"), Some(&spec));
    assert_eq!(registry.get_cwe("89"), None);
}

#[test]
fn test_router_registry_language_override() {
    let mut registry = RouterRegistry::new();

    let spec = PromptSpec {
        prompt_template: "rust_template".to_string(),
        model_override: None,
    };

    registry.add_language_override("rust".to_string(), spec.clone());

    assert_eq!(registry.get_language("rust"), Some(&spec));
    assert_eq!(registry.get_language("c"), None);
}

#[test]
fn test_cwe_router_default_instance() {
    let router = CweRouter::default();
    assert_eq!(router.default_prompt(), "llm_static_analysis");

    // Should fall back to default for any input
    let spec = router.route(&Some("79".to_string()), "c");
    assert_eq!(spec.prompt_template, "llm_static_analysis");
}

#[test]
fn test_cwe_casing_normalization() {
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

    // Should match regardless of CWE format
    assert!(router.route_by_cwe("79").is_some());
    assert!(router.route_by_cwe("CWE-79").is_some());
    assert!(router.route_by_cwe("cwe-79").is_some());
}
