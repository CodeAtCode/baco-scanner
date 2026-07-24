//! Unit tests for the MoE router module
//!
//! Tests cover RouterRegistry, CweRouter, and routing logic including
//! edge cases, error paths, and priority resolution.

use baco::router::{CweRouter, PromptSpec, RouterConfig, RouterRegistry};
use std::collections::HashMap;

// ============================================================================
// RouterRegistry Tests
// ============================================================================

#[test]
fn test_registry_new_creates_empty_registry() {
    let registry = RouterRegistry::new();
    assert!(registry.get_cwe("79").is_none());
    assert!(registry.get_language("rust").is_none());
}

#[test]
fn test_registry_add_multiple_cwe_overrides() {
    let mut registry = RouterRegistry::new();

    let spec_79 = PromptSpec {
        prompt_template: "xss_prompt".to_string(),
        model_override: None,
    };
    let spec_89 = PromptSpec {
        prompt_template: "sqli_prompt".to_string(),
        model_override: Some("model-a".to_string()),
    };

    registry.add_cwe_override("79".to_string(), spec_79.clone());
    registry.add_cwe_override("89".to_string(), spec_89.clone());

    assert_eq!(registry.get_cwe("79"), Some(&spec_79));
    assert_eq!(registry.get_cwe("89"), Some(&spec_89));
    assert!(registry.get_cwe("88").is_none());
}

#[test]
fn test_registry_add_multiple_language_overrides() {
    let mut registry = RouterRegistry::new();

    let spec_rust = PromptSpec {
        prompt_template: "rust_prompt".to_string(),
        model_override: None,
    };
    let spec_c = PromptSpec {
        prompt_template: "c_prompt".to_string(),
        model_override: None,
    };

    registry.add_language_override("rust".to_string(), spec_rust.clone());
    registry.add_language_override("c".to_string(), spec_c.clone());

    assert_eq!(registry.get_language("rust"), Some(&spec_rust));
    assert_eq!(registry.get_language("c"), Some(&spec_c));
    assert!(registry.get_language("python").is_none());
}

#[test]
fn test_registry_override_replaces_existing() {
    let mut registry = RouterRegistry::new();

    let spec_first = PromptSpec {
        prompt_template: "first".to_string(),
        model_override: None,
    };
    let spec_second = PromptSpec {
        prompt_template: "second".to_string(),
        model_override: None,
    };

    registry.add_cwe_override("79".to_string(), spec_first.clone());
    registry.add_cwe_override("79".to_string(), spec_second.clone());

    assert_eq!(registry.get_cwe("79"), Some(&spec_second));
}

// ============================================================================
// CweRouter Tests
// ============================================================================

#[test]
fn test_router_from_scanner_config() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "123".to_string(),
        PromptSpec {
            prompt_template: "scanner_test".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "scanner_default".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_scanner_config(&config);
    assert_eq!(router.default_prompt(), "scanner_default");

    let spec = router.route_by_cwe("123").unwrap();
    assert_eq!(spec.prompt_template, "scanner_test");
}

#[test]
fn test_router_route_with_none_cwe() {
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "rust".to_string(),
        PromptSpec {
            prompt_template: "rust_lang".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "default_prompt".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // None CWE should fall back to language or default
    let spec = router.route(&None, "rust");
    assert_eq!(spec.prompt_template, "rust_lang");
}

#[test]
fn test_router_route_with_empty_language() {
    let config = RouterConfig {
        enabled: true,
        default_prompt: "fallback".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // Empty language with no CWE should use default
    let spec = router.route(&None, "");
    assert_eq!(spec.prompt_template, "fallback");
}

#[test]
fn test_router_route_cwe_priority_over_language() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "cwe_priority".to_string(),
            model_override: None,
        },
    );

    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "rust".to_string(),
        PromptSpec {
            prompt_template: "lang_fallback".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "default_prompt".to_string(),
        cwe_overrides,
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // CWE match takes priority
    let spec = router.route(&Some("79".to_string()), "rust");
    assert_eq!(spec.prompt_template, "cwe_priority");
}

#[test]
fn test_router_route_language_fallback_when_cwe_missing() {
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "go".to_string(),
        PromptSpec {
            prompt_template: "go_lang".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "default_prompt".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // Unknown CWE should fall back to language
    let spec = router.route(&Some("999".to_string()), "go");
    assert_eq!(spec.prompt_template, "go_lang");
}

#[test]
fn test_router_route_complete_fallback_to_default() {
    let config = RouterConfig {
        enabled: true,
        default_prompt: "ultimate_fallback".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // No matches anywhere should use default
    let spec = router.route(&Some("999".to_string()), "unknown");
    assert_eq!(spec.prompt_template, "ultimate_fallback");
}

#[test]
fn test_router_route_by_cwe_with_various_formats() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "416".to_string(),
        PromptSpec {
            prompt_template: "uaf_prompt".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "default".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // All formats should resolve to the same spec
    assert!(router.route_by_cwe("416").is_some());
    assert!(router.route_by_cwe("CWE-416").is_some());
    assert!(router.route_by_cwe("cwe-416").is_some());
}

#[test]
fn test_router_route_by_language_case_sensitive() {
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "Rust".to_string(),
        PromptSpec {
            prompt_template: "capital_rust".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "default".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // Language matching is case-sensitive
    assert!(router.route_by_language("Rust").is_some());
    assert!(router.route_by_language("rust").is_none());
    assert!(router.route_by_language("RUST").is_none());
}

#[test]
fn test_router_default_prompt_variations() {
    let config_default = RouterConfig::default();
    let router_default = CweRouter::from_config(&config_default);
    assert_eq!(router_default.default_prompt(), "llm_static_analysis");

    let config_custom = RouterConfig {
        enabled: true,
        default_prompt: "my_custom_prompt".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    };
    let router_custom = CweRouter::from_config(&config_custom);
    assert_eq!(router_custom.default_prompt(), "my_custom_prompt");
}

#[test]
fn test_router_with_model_override_propagation() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "78".to_string(),
        PromptSpec {
            prompt_template: "os_commanding".to_string(),
            model_override: Some("special-model-v2".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "default".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    let spec = router.route(&Some("78".to_string()), "any");
    assert_eq!(spec.prompt_template, "os_commanding");
    assert_eq!(spec.model_override, Some("special-model-v2".to_string()));
}

// ============================================================================
// normalize_cwe_id Edge Cases
// ============================================================================

#[test]
fn test_normalize_cwe_id_various_formats() {
    use baco::router::CweRouter;
    use std::collections::HashMap;

    let mut cwe_overrides = HashMap::new();
    // Store with normalized form
    cwe_overrides.insert(
        "95".to_string(),
        PromptSpec {
            prompt_template: "env_injection".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "default".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // All variations should match
    assert!(router.route_by_cwe("95").is_some());
    assert!(router.route_by_cwe("CWE-95").is_some());
    assert!(router.route_by_cwe("cwe-95").is_some());
}

#[test]
fn test_router_empty_cwe_overrides_uses_default() {
    let config = RouterConfig {
        enabled: true,
        default_prompt: "only_default".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // Empty overrides means everything falls back to default
    let spec = router.route(&Some("123".to_string()), "lang");
    assert_eq!(spec.prompt_template, "only_default");
}

#[test]
fn test_router_both_cwe_and_language_match_cwe_wins() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "22".to_string(),
        PromptSpec {
            prompt_template: "path_traversal_cwe".to_string(),
            model_override: None,
        },
    );

    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "typescript".to_string(),
        PromptSpec {
            prompt_template: "path_traversal_lang".to_string(),
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "default".to_string(),
        cwe_overrides,
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // CWE should win even when both match
    let spec = router.route(&Some("22".to_string()), "typescript");
    assert_eq!(spec.prompt_template, "path_traversal_cwe");
}
