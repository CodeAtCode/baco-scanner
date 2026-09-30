//! Unit tests for the MoE router module (domain-based routing)
//!
//! Tests cover RouterRegistry domain configuration and CweRouter CWE routing.

use baco::config::{PromptSpec, RouterConfig};
use baco::router::{CweRouter, RouterRegistry};
use std::collections::HashMap;

// ============================================================================
// RouterRegistry Domain Tests
// ============================================================================

#[test]
fn test_registry_new_creates_empty_registry() {
    let registry = RouterRegistry::new();
    assert!(registry.get_domain("xss").is_none());
    assert!(registry.get_domain("injection").is_none());
}

#[test]
fn test_registry_add_multiple_domains() {
    let mut registry = RouterRegistry::new();

    let config_xss = baco::router::DomainConfig {
        model_override: None,
    };
    let config_injection = baco::router::DomainConfig {
        model_override: Some("model-a".to_string()),
    };

    registry.add_domain("xss".to_string(), config_xss);
    registry.add_domain("injection".to_string(), config_injection);

    assert!(registry.get_domain("xss").is_some());
    assert!(registry.get_domain("injection").is_some());
    assert!(registry.get_domain("auth").is_none());
}

#[test]
fn test_registry_override_replaces_existing() {
    let mut registry = RouterRegistry::new();

    let config_first = baco::router::DomainConfig {
        model_override: Some("first-model".to_string()),
    };
    let config_second = baco::router::DomainConfig {
        model_override: Some("second-model".to_string()),
    };

    registry.add_domain("xss".to_string(), config_first);
    registry.add_domain("xss".to_string(), config_second.clone());

    let found = registry.get_domain("xss").unwrap();
    assert_eq!(found.model_override, Some("second-model".to_string()));
}

// ============================================================================
// CweRouter Domain-Based Routing Tests
// ============================================================================

#[test]
fn test_router_from_scanner_config() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "CWE-123".to_string(),
        PromptSpec {
            model_override: None,
        },
    );

    let config = RouterConfig {
        enabled: true,
        cwe_overrides,
    };

    let router = CweRouter::from_scanner_config(&config);

    let route = router.route_cwe("CWE-123");
    // CWE-123 has no domain mapping, so returns no domain
    assert_eq!(route.domain, None);
}

#[test]
fn test_router_route_cwe_with_known_cwe() {
    let router = CweRouter::default();

    let route = router.route_cwe("CWE-79");
    assert_eq!(route.domain.as_deref(), Some("xss"));
    assert_eq!(route.model_override, None);
}

#[test]
fn test_router_route_cwe_with_unknown_cwe() {
    let router = CweRouter::default();

    let route = router.route_cwe("CWE-999999");
    assert_eq!(route.domain, None);
    assert_eq!(route.model_override, None);
}

#[test]
fn test_router_route_by_cwe_with_various_formats() {
    let router = CweRouter::default();

    // Only prefixed "CWE-" format (case-sensitive) matches
    assert_eq!(
        router.route_cwe("CWE-400").domain.as_deref(),
        Some("resource")
    );

    // Bare "400" does NOT match (requires "CWE-" prefix)
    assert_eq!(router.route_cwe("400").domain.as_deref(), None);

    // Lowercase "cwe-400" does NOT match (case-sensitive)
    assert_eq!(router.route_cwe("cwe-400").domain.as_deref(), None);
}

#[test]
fn test_router_with_model_override_propagation() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "CWE-78".to_string(),
        PromptSpec {
            model_override: Some("special-model-v2".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        cwe_overrides,
    };

    let router = CweRouter::from_config(&config);

    let route = router.route_cwe("CWE-78");
    assert_eq!(route.domain.as_deref(), Some("injection"));
    assert_eq!(route.model_override.as_deref(), Some("special-model-v2"));
}

// ============================================================================
// CWE-to-Domain Mapping Tests
// ============================================================================

#[test]
fn test_multiple_domains_mapping() {
    let router = CweRouter::default();

    assert_eq!(router.route_cwe("CWE-79").domain.as_deref(), Some("xss"));
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

#[test]
fn test_router_empty_cwe_overrides_registers_no_model_override() {
    let config = RouterConfig {
        enabled: true,
        cwe_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // No overrides registered, so even a mapped CWE carries no model override.
    assert_eq!(router.route_cwe("CWE-78").model_override, None);
}

#[test]
fn test_router_default_registry_seeds_domains() {
    let config = RouterConfig::default();
    let router = CweRouter::from_config(&config);

    // Default registry should have domain mappings from registry.toml
    let route = router.route_cwe("CWE-79");
    assert_eq!(route.domain.as_deref(), Some("xss"));
}
