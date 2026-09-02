//! Tests for MoE CWE router wired to hunt-domain prompt content.
//!
//! Tests verify:
//! 1. route_cwe("CWE-79") → domain Some("xss") with model_override from registry
//! 2. hunt_prompt_for_cwe("CWE-89") returns injection module content (non-empty, contains "Scope — stay in your lane")
//! 3. unknown CWE (CWE-999999) → None/uncategorized gracefully
//! 4. registry.toml parses and every domain key maps to an existing prompts/hunt/<domain>.md file

use std::fs;
use std::path::Path;

#[test]
fn test_route_cwe_79_xss_domain() {
    use baco::router::CweRouter;

    let router = CweRouter::default();
    let route = router.route_cwe("CWE-79");

    assert_eq!(route.domain, Some("xss".to_string()));
    // Model override should be None as per registry.toml
    assert_eq!(route.model_override, None);
}

#[test]
fn test_route_cwe_89_injection_domain() {
    use baco::router::CweRouter;

    let router = CweRouter::default();
    let route = router.route_cwe("CWE-89");

    assert_eq!(route.domain, Some("injection".to_string()));
    assert_eq!(route.model_override, None);
}

#[test]
fn test_hunt_prompt_for_cwe_89_injection_content() {
    use baco::prompt::engine::PromptEngine;

    let engine = PromptEngine::new();
    let prompt = engine.hunt_prompt_for_cwe("CWE-89");

    assert!(prompt.is_some(), "CWE-89 should map to injection prompt");
    let content = prompt.unwrap();
    assert!(
        !content.is_empty(),
        "Injection prompt content should not be empty"
    );
    // Verify it contains the argus work marker
    assert!(
        content.contains("Scope — stay in your lane"),
        "Injection prompt should contain 'Scope — stay in your lane' from argus work"
    );
}

#[test]
fn test_hunt_prompt_for_cwe_79_xss_content() {
    use baco::prompt::engine::PromptEngine;

    let engine = PromptEngine::new();
    let prompt = engine.hunt_prompt_for_cwe("CWE-79");

    assert!(prompt.is_some(), "CWE-79 should map to xss prompt");
    let content = prompt.unwrap();
    assert!(
        !content.is_empty(),
        "XSS prompt content should not be empty"
    );
}

#[test]
fn test_unknown_cwe_returns_none() {
    use baco::prompt::engine::PromptEngine;
    use baco::router::CweRouter;

    // Test router
    let router = CweRouter::default();
    let route = router.route_cwe("CWE-999999");
    assert_eq!(
        route.domain, None,
        "Unknown CWE should return uncategorized route"
    );
    assert_eq!(route.model_override, None);

    // Test engine
    let engine = PromptEngine::new();
    let prompt = engine.hunt_prompt_for_cwe("CWE-999999");
    assert!(
        prompt.is_none(),
        "Unknown CWE should return None for prompt content"
    );
}

#[test]
fn test_cwe_specialist_context_known_cwe() {
    use baco::router::cwe_specialist_context;

    let result = cwe_specialist_context("CWE-79");
    assert!(result.is_some(), "CWE-79 should return specialist context");
    let (domain, content) = result.unwrap();
    assert_eq!(domain, "xss");
    assert!(!content.is_empty(), "Content should not be empty");
}

#[test]
fn test_cwe_specialist_context_unknown_cwe() {
    use baco::router::cwe_specialist_context;

    let result = cwe_specialist_context("CWE-999999");
    assert!(result.is_none(), "Unknown CWE should return None");
}

#[test]
fn test_registry_parses_and_domains_exist() {
    use baco::router::DomainConfig;
    use std::collections::HashSet;

    // Read the registry.toml file
    let registry_content =
        fs::read_to_string("src/router/registry.toml").expect("Should read registry.toml");

    // Parse using toml - match the actual TOML structure with [router] and [router.domains]
    #[derive(serde::Deserialize)]
    struct RegistryRoot {
        router: RouterSection,
    }

    #[derive(serde::Deserialize)]
    struct RouterSection {
        #[serde(default)]
        domains: std::collections::HashMap<String, DomainConfig>,
    }

    let root: RegistryRoot = toml::from_str(&registry_content).expect("Should parse registry.toml");
    let registry_domains: HashSet<String> = root.router.domains.keys().cloned().collect();

    // Verify each domain has a corresponding file in prompts/hunt/
    let hunt_dir = Path::new("prompts/hunt");
    assert!(hunt_dir.exists(), "prompts/hunt directory should exist");

    for domain in &registry_domains {
        let expected_file = hunt_dir.join(format!("{}.md", domain));
        assert!(
            expected_file.exists(),
            "Domain '{}' should have corresponding file: {:?}",
            domain,
            expected_file
        );
    }

    // Verify all expected domains are present and check model_override field
    let expected_domains = [
        "injection",
        "xss",
        "auth",
        "authz_absence",
        "path_traversal",
        "crypto",
        "resource",
        "deserialization",
        "memory_safety",
    ];

    for domain in &expected_domains {
        assert!(
            registry_domains.contains(*domain),
            "Registry should contain domain: {}",
            domain
        );

        // Verify model_override is None as per registry.toml
        let config = root.router.domains.get(*domain).unwrap();
        assert_eq!(
            config.model_override, None,
            "Domain '{}' should have model_override = None per registry.toml",
            domain
        );
    }
}

#[test]
fn test_all_cwe_mappings_have_corresponding_prompts() {
    use baco::prompt::engine::PromptEngine;
    use baco::prompt::templates::cwe_to_hunt_domain;

    let engine = PromptEngine::new();

    // Test all CWE IDs from the mapping
    let test_cases = vec![
        ("CWE-89", "injection"),
        ("CWE-78", "injection"),
        ("CWE-90", "injection"),
        ("CWE-119", "injection"),
        ("CWE-79", "xss"),
        ("CWE-80", "xss"),
        ("CWE-287", "auth"),
        ("CWE-285", "auth"),
        ("CWE-290", "auth"),
        ("CWE-22", "path_traversal"),
        ("CWE-23", "path_traversal"),
        ("CWE-36", "path_traversal"),
        ("CWE-327", "crypto"),
        ("CWE-328", "crypto"),
        ("CWE-757", "crypto"),
        ("CWE-400", "resource"),
        ("CWE-770", "resource"),
        ("CWE-190", "resource"),
        ("CWE-502", "deserialization"),
        ("CWE-503", "deserialization"),
        ("CWE-20", "deserialization"),
    ];

    for (cwe_id, expected_domain) in test_cases {
        // Verify CWE maps to expected domain
        let domain = cwe_to_hunt_domain(cwe_id);
        assert_eq!(
            domain,
            Some(expected_domain),
            "CWE-{} should map to {}",
            cwe_id,
            expected_domain
        );

        // Verify the hunt prompt exists for this domain
        let prompt = engine.hunt_prompt_for_cwe(cwe_id);
        assert!(
            prompt.is_some() && !prompt.as_ref().unwrap().is_empty(),
            "CWE-{} (domain: {}) should have non-empty prompt content",
            cwe_id,
            expected_domain
        );
    }
}
