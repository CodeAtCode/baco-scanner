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
    let spec = router.route(&Some("79".to_string()), "rust");
    assert_eq!(spec.prompt_template, "llm_static_analysis");
    assert!(spec.model_override.is_none());
}

#[test]
fn test_cwe_router_cwe_override_sets_model() {
    let config = enabled_config_with_cwe_override("79", "claude-3-opus");
    let router = CweRouter::from_config(&config);

    let spec = router.route(&Some("79".to_string()), "javascript");
    assert_eq!(spec.prompt_template, "specialized_prompt");
    assert_eq!(spec.model_override.as_deref(), Some("claude-3-opus"));
}

#[test]
fn test_cwe_router_normalized_cwe_id() {
    let config = enabled_config_with_cwe_override("79", "claude-3-opus");
    let router = CweRouter::from_config(&config);

    // "CWE-79" should match "79"
    let spec = router.route(&Some("CWE-79".to_string()), "javascript");
    assert_eq!(spec.model_override.as_deref(), Some("claude-3-opus"));

    // "cwe-79" should also match
    let spec = router.route(&Some("cwe-79".to_string()), "javascript");
    assert_eq!(spec.model_override.as_deref(), Some("claude-3-opus"));
}

#[test]
fn test_cwe_router_language_override() {
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "rust".to_string(),
        PromptSpec {
            prompt_template: "rust_specialized".to_string(),
            model_override: Some("codegeex".to_string()),
        },
    );
    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };
    let router = CweRouter::from_config(&config);

    let spec = router.route(&None, "rust");
    assert_eq!(spec.prompt_template, "rust_specialized");
    assert_eq!(spec.model_override.as_deref(), Some("codegeex"));
}

#[test]
fn test_cwe_router_cwe_priority_over_language() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "cwe_79_prompt".to_string(),
            model_override: Some("cwe_model".to_string()),
        },
    );
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "javascript".to_string(),
        PromptSpec {
            prompt_template: "js_prompt".to_string(),
            model_override: Some("js_model".to_string()),
        },
    );
    let config = RouterConfig {
        enabled: true,
        default_prompt: "default".to_string(),
        cwe_overrides,
        language_overrides,
    };
    let router = CweRouter::from_config(&config);

    // CWE match should take priority over language match
    let spec = router.route(&Some("CWE-79".to_string()), "javascript");
    assert_eq!(spec.prompt_template, "cwe_79_prompt");
    assert_eq!(spec.model_override.as_deref(), Some("cwe_model"));
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

    let spec = router.route(&Some("999".to_string()), "cobol");
    assert_eq!(spec.prompt_template, "my_default_prompt");
    assert!(spec.model_override.is_none());
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
    let config = enabled_config_with_cwe_override("89", "gpt-4-security");
    let router = CweRouter::from_config(&config);

    let mut findings = vec![
        make_finding("f1", Some("79"), "src/main.rs"),
        make_finding("f2", Some("89"), "src/db.rs"),
        make_finding("f3", None, "src/utils.py"),
    ];

    // Simulate CweRouting phase logic
    for finding in &mut findings {
        let language = baco::report::html::utilities::detect_language(&finding.file_path);
        let spec = router.route(&finding.cwe_id, language);
        if let Some(ref model) = spec.model_override {
            finding.llm_model = Some(model.clone());
        }
    }

    // f1: CWE-79, no override → None
    assert!(findings[0].llm_model.is_none());

    // f2: CWE-89, has override → Some("gpt-4-security")
    assert_eq!(findings[1].llm_model.as_deref(), Some("gpt-4-security"));

    // f3: no CWE, no language override → None
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
    let config = enabled_config_with_cwe_override("79", "model-a");
    let router = CweRouter::from_config(&config);

    let mut findings = vec![
        make_finding("f1", Some("CWE-79"), "app.js"),
        make_finding("f2", Some("79"), "handler.py"),
        make_finding("f3", Some("89"), "db.go"),
    ];

    let mut routed_count = 0usize;
    for finding in &mut findings {
        let language = baco::report::html::utilities::detect_language(&finding.file_path);
        let spec = router.route(&finding.cwe_id, language);
        if let Some(ref model) = spec.model_override {
            finding.llm_model = Some(model.clone());
            routed_count += 1;
        }
    }

    assert_eq!(routed_count, 2);
    assert_eq!(findings[0].llm_model.as_deref(), Some("model-a"));
    assert_eq!(findings[1].llm_model.as_deref(), Some("model-a"));
    assert!(findings[2].llm_model.is_none());
}
