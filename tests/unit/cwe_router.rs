//! Tests for the MoE per-CWE router (domain-based routing)

use baco::config::{PromptSpec, RouterConfig};
use baco::router::{CweRouter, RouterRegistry};
use std::collections::HashMap;

/// CWE-79 routes to the xss hunt domain
#[test]
fn test_route_by_cwe_79_returns_xss_domain() {
    let router = CweRouter::default();
    let route = router.route_cwe("CWE-79");
    assert_eq!(route.domain.as_deref(), Some("xss"));
}

/// CWE-89 routes to the injection hunt domain
#[test]
fn test_route_by_cwe_89_returns_injection_domain() {
    let router = CweRouter::default();
    let route = router.route_cwe("CWE-89");
    assert_eq!(route.domain.as_deref(), Some("injection"));
}

/// Unknown CWEs have no domain
#[test]
fn test_route_by_cwe_unknown_has_no_domain() {
    let router = CweRouter::default();
    let route = router.route_cwe("unknown");
    assert_eq!(route.domain, None);
    assert_eq!(route.model_override, None);
}

/// RouterConfig default values
#[test]
fn test_router_config_default() {
    let config = RouterConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.default_prompt, "llm_static_analysis");
    assert!(config.cwe_overrides.is_empty());
}

/// RouterRegistry supports domain-based configuration
#[test]
fn test_router_registry_add_domain() {
    let mut registry = RouterRegistry::new();

    let config = baco::router::DomainConfig {
        model_override: Some("custom-model".to_string()),
    };

    registry.add_domain("xss".to_string(), config);

    assert!(registry.get_domain("xss").is_some());
    assert!(registry.get_domain("injection").is_none());
}

/// RouterRegistry domain lookup returns correct model override
#[test]
fn test_router_registry_get_domain_config() {
    let mut registry = RouterRegistry::new();

    let config = baco::router::DomainConfig {
        model_override: Some("mistral-large".to_string()),
    };

    registry.add_domain("injection".to_string(), config.clone());

    let found = registry.get_domain("injection").unwrap();
    assert_eq!(found.model_override, Some("mistral-large".to_string()));
}

/// CWE casing normalization - prefixed "CWE-" is required (case-sensitive)
#[test]
fn test_cwe_casing_normalization() {
    let router = CweRouter::default();

    // "CWE-79" (prefixed, correct case) routes to xss domain
    assert_eq!(router.route_cwe("CWE-79").domain.as_deref(), Some("xss"));

    // Bare "79" does NOT match (cwe_to_hunt_domain requires "CWE-" prefix)
    assert_eq!(router.route_cwe("79").domain.as_deref(), None);

    // Lowercase "cwe-79" does NOT match (case-sensitive)
    assert_eq!(router.route_cwe("cwe-79").domain.as_deref(), None);
}

/// Model override propagates through domain routing
#[test]
fn test_model_override_propagation() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "CWE-89".to_string(),
        PromptSpec {
            prompt_template: "llm_static_analysis".to_string(),
            model_override: Some("special-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);
    let route = router.route_cwe("CWE-89");

    assert_eq!(route.domain.as_deref(), Some("injection"));
    assert_eq!(route.model_override.as_deref(), Some("special-model"));
}

/// Default prompt accessible from router
#[test]
fn test_cwe_router_default_prompt() {
    let router = CweRouter::default();
    assert_eq!(router.default_prompt(), "llm_static_analysis");
}

/// Custom default prompt from config
#[test]
fn test_cwe_router_custom_default_prompt() {
    let config = RouterConfig {
        enabled: true,
        default_prompt: "my_custom_prompt".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);
    assert_eq!(router.default_prompt(), "my_custom_prompt");
}
