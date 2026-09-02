//! Integration tests for the MoE CWE router pipeline (domain-based routing).

use baco::config::{PromptSpec, RouterConfig};
use baco::router::CweRouter;
use std::collections::HashMap;

fn config_with_override(cwe: &str, model: Option<&str>) -> RouterConfig {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        cwe.to_string(),
        PromptSpec {
            prompt_template: "llm_static_analysis".to_string(),
            model_override: model.map(|m| m.to_string()),
        },
    );
    RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    }
}

fn empty_config() -> RouterConfig {
    RouterConfig {
        enabled: false,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    }
}

/// CWE-79 routes to the xss hunt domain
#[test]
fn test_moe_cwe_79_routes_to_xss_domain() {
    let router = CweRouter::from_config(&config_with_override("CWE-79", None));
    let route = router.route_cwe("CWE-79");
    assert_eq!(route.domain.as_deref(), Some("xss"));
}

/// Unknown CWEs fall back to no domain and no override
#[test]
fn test_moe_unknown_cwe_has_no_domain() {
    let router = CweRouter::from_config(&config_with_override("CWE-79", None));
    let route = router.route_cwe("CWE-999999");
    assert_eq!(route.domain, None);
    assert_eq!(route.model_override, None);
}

/// A CWE override configured by model propagates through its domain
#[test]
fn test_moe_model_override_propagates_through_domain() {
    let router = CweRouter::from_config(&config_with_override("CWE-89", Some("mistral-large")));
    let route = router.route_cwe("CWE-89");
    assert_eq!(route.domain.as_deref(), Some("injection"));
    assert_eq!(route.model_override.as_deref(), Some("mistral-large"));
}

/// Multiple CWE families map to their hunt domains
#[test]
fn test_moe_multiple_domains() {
    let router = CweRouter::from_config(&config_with_override("CWE-79", None));
    assert_eq!(
        router.route_cwe("CWE-89").domain.as_deref(),
        Some("injection")
    );
    assert_eq!(
        router.route_cwe("CWE-22").domain.as_deref(),
        Some("path_traversal")
    );
    assert_eq!(
        router.route_cwe("CWE-327").domain.as_deref(),
        Some("crypto")
    );
    assert_eq!(
        router.route_cwe("CWE-502").domain.as_deref(),
        Some("deserialization")
    );
    assert_eq!(router.route_cwe("CWE-287").domain.as_deref(), Some("auth"));
}

/// The shipped registry.toml seeds domain knowledge even without config overrides
#[test]
fn test_moe_default_registry_seeds_domains() {
    let router = CweRouter::from_config(&empty_config());
    let route = router.route_cwe("CWE-79");
    assert_eq!(route.domain.as_deref(), Some("xss"));
    assert_eq!(route.model_override, None);
}
