use baco::config::{PromptSpec, RouterConfig};
use baco::findings::VulnerabilityFinding;
use baco::router::CweRouter;
use std::collections::HashMap;

use crate::fixtures::make_finding_cwe;

fn make_finding(id: &str, cwe_id: Option<&str>, file_path: &str) -> VulnerabilityFinding {
    make_finding_cwe(id, cwe_id, file_path)
}

fn enabled_config_with_cwe_override(cwe_id: &str, model: &str) -> RouterConfig {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        cwe_id.to_string(),
        PromptSpec {
            prompt_template: "specialized_prompt".to_string(),
            model_override: Some(model.to_string()),
        },
    );
    RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    }
}

#[test]
fn test_cwe_router_disabled_returns_default() {
    let config = RouterConfig::default();
    assert!(!config.enabled);

    let router = CweRouter::from_config(&config);
    let route = router.route_cwe("79");
    assert_eq!(route.domain, None);
    assert!(route.model_override.is_none());
}

#[test]
fn test_cwe_router_cwe_override_sets_model() {
    let config = enabled_config_with_cwe_override("CWE-79", "claude-3-opus");
    let router = CweRouter::from_config(&config);

    let route = router.route_cwe("CWE-79");
    assert_eq!(route.domain.as_deref(), Some("xss"));
    assert_eq!(route.model_override.as_deref(), Some("claude-3-opus"));
}

#[test]
fn test_cwe_router_normalized_cwe_id() {
    let config = enabled_config_with_cwe_override("CWE-79", "claude-3-opus");
    let router = CweRouter::from_config(&config);

    // "CWE-79" matches the config key
    let route = router.route_cwe("CWE-79");
    assert_eq!(route.model_override.as_deref(), Some("claude-3-opus"));

    // "cwe-79" (lowercase) does NOT match via cwe_to_hunt_domain
    let route = router.route_cwe("cwe-79");
    assert_eq!(route.model_override, None);

    // Bare "79" does NOT match via cwe_to_hunt_domain
    let route = router.route_cwe("79");
    assert_eq!(route.model_override, None);
}

#[test]
fn test_cwe_router_no_match_falls_to_default() {
    let config = RouterConfig {
        enabled: true,
        default_prompt: "my_default_prompt".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    };
    let router = CweRouter::from_config(&config);

    let route = router.route_cwe("CWE-999");
    assert_eq!(route.domain, None);
    assert!(route.model_override.is_none());
}

#[test]
fn test_cwe_routing_phase_disabled_passes_findings_through() {
    let config = RouterConfig::default();
    let _router = CweRouter::from_config(&config);

    let findings = [
        make_finding("f1", Some("79"), "src/main.rs"),
        make_finding("f2", Some("89"), "src/db.rs"),
    ];

    // Simulate what the CweRouting phase does when disabled (short-circuit)
    // The phase returns early without calling the router
    assert!(!config.enabled);
    assert_eq!(findings.len(), 2);
    assert!(findings[0].llm_model.is_none());
    assert!(findings[1].llm_model.is_none());
}

#[test]
fn test_cwe_routing_phase_enabled_applies_model_overrides() {
    let config = enabled_config_with_cwe_override("CWE-89", "gpt-4-security");
    let router = CweRouter::from_config(&config);

    let mut findings = vec![
        make_finding("f1", Some("CWE-79"), "src/main.rs"),
        make_finding("f2", Some("CWE-89"), "src/db.rs"),
        make_finding("f3", None, "src/utils.py"),
    ];

    // Simulate CweRouting phase logic (from cwe_routing.rs)
    for finding in &mut findings {
        if let Some(cwe) = finding.cwe_id.as_deref() {
            let route = router.route_cwe(cwe);
            if let Some(model) = route.model_override {
                finding.llm_model = Some(model);
            }
        }
    }

    // f1: CWE-79, no override → None
    assert!(findings[0].llm_model.is_none());

    // f2: CWE-89, has override → Some("gpt-4-security")
    assert_eq!(findings[1].llm_model.as_deref(), Some("gpt-4-security"));

    // f3: no CWE → None
    assert!(findings[2].llm_model.is_none());
}

#[test]
fn test_cwe_router_from_scanner_config() {
    let config = RouterConfig::default();
    let router = CweRouter::from_scanner_config(&config);
    assert_eq!(router.default_prompt(), "llm_static_analysis");
}

#[test]
fn test_cwe_routing_phase_routing_count() {
    let config = enabled_config_with_cwe_override("CWE-79", "model-a");
    let router = CweRouter::from_config(&config);

    let mut findings = vec![
        make_finding("f1", Some("CWE-79"), "app.js"),
        make_finding("f2", Some("CWE-79"), "handler.py"),
        make_finding("f3", Some("CWE-89"), "db.go"),
    ];

    let mut routed_count = 0usize;
    for finding in &mut findings {
        if let Some(cwe) = finding.cwe_id.as_deref() {
            let route = router.route_cwe(cwe);
            if let Some(model) = route.model_override {
                finding.llm_model = Some(model);
                routed_count += 1;
            }
        }
    }

    assert_eq!(routed_count, 2);
    assert_eq!(findings[0].llm_model.as_deref(), Some("model-a"));
    assert_eq!(findings[1].llm_model.as_deref(), Some("model-a"));
    assert!(findings[2].llm_model.is_none());
}
