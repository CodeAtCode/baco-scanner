//! Unit tests for the CweRouting phase logic
//!
//! These tests verify the MoE CWE routing functionality:
//! - Pass-through when router is disabled
//! - Model routing when router is enabled
//! - CWE override application
//! - Language override application
//! - Multiple findings routing
//!
//! Note: These tests test the router logic directly since the phases module is private.
//! The CweRouting phase in src/scanner/phases.rs uses CweRouter::route() which is what we test here.

use baco::config::{PromptSpec, RouterConfig};
use baco::findings::Severity;
use baco::report::html::utilities;
use baco::router::CweRouter;
use std::collections::HashMap;

/// Create a test finding with specific CWE ID and file path
fn create_finding_with_cwe(
    cwe_id: Option<String>,
    file_path: &str,
    severity: Severity,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: format!(
            "test-{}",
            cwe_id.as_deref().unwrap_or("no-cwe").to_lowercase()
        ),
        title: format!("Test {}", cwe_id.as_deref().unwrap_or("no-cwe")),
        description: format!("Test finding for {}", cwe_id.as_deref().unwrap_or("no-cwe")),
        severity,
        confidence_score: 0.8,
        cwe_id,
        file_path: file_path.to_string(),
        line_number: Some(10),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

/// Simulate the CweRouting phase logic (from src/scanner/phases.rs lines 1233-1261)
/// This is what the phase does when router is enabled:
/// 1. Create router from config
/// 2. For each finding, detect language and route
/// 3. If model_override is Some, set finding.llm_model
fn simulate_cwe_routing(findings: &mut [baco::findings::VulnerabilityFinding], router: &CweRouter) {
    for finding in findings {
        let language = utilities::detect_language(&finding.file_path);
        let spec = router.route(&finding.cwe_id, language);

        if let Some(ref model) = spec.model_override {
            finding.llm_model = Some(model.clone());
        }
    }
}

// ============================================================================
// Test: CweRouting disabled pass-through
// ============================================================================

#[test]
fn test_cwe_routing_disabled_pass_through() {
    // When router is disabled (config.router.enabled = false), findings pass through unchanged
    let config = RouterConfig {
        enabled: false,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);
    let mut findings = vec![
        create_finding_with_cwe(Some("CWE-79".to_string()), "src/app.rs", Severity::High),
        create_finding_with_cwe(Some("CWE-89".to_string()), "src/db.rs", Severity::Critical),
    ];

    simulate_cwe_routing(&mut findings, &router);

    // All findings should remain unchanged (no llm_model set)
    for finding in &findings {
        assert!(
            finding.llm_model.is_none(),
            "Finding should not have model set when router is disabled"
        );
    }
}

// ============================================================================
// Test: CweRouting enabled without CWE override (default model)
// ============================================================================

#[test]
fn test_cwe_routing_enabled_no_cwe_override() {
    // Router enabled but no CWE override - should use default (no model set)
    let mut cwe_overrides = HashMap::new();
    // Add a CWE override but NOT for the CWE we're testing
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: Some("xss-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // Create finding with CWE-89 (no override)
    let mut findings = vec![create_finding_with_cwe(
        Some("CWE-89".to_string()),
        "src/db.rs",
        Severity::Critical,
    )];

    simulate_cwe_routing(&mut findings, &router);

    // Finding should not have model set (no override for CWE-89 and no language override)
    assert!(
        findings[0].llm_model.is_none(),
        "Finding without CWE override should not have model set"
    );
}

// ============================================================================
// Test: CweRouting enabled with CWE override (model_override applied)
// ============================================================================

#[test]
fn test_cwe_routing_enabled_with_cwe_override() {
    // Router enabled with CWE override - model should be applied
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "89".to_string(),
        PromptSpec {
            prompt_template: "sqli_specialized".to_string(),
            model_override: Some("sqli-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    let mut findings = vec![create_finding_with_cwe(
        Some("CWE-89".to_string()),
        "src/db.rs",
        Severity::Critical,
    )];

    simulate_cwe_routing(&mut findings, &router);

    // Finding should have the model override applied
    assert_eq!(findings[0].llm_model, Some("sqli-model".to_string()));
}

// ============================================================================
// Test: CweRouting enabled with language override
// ============================================================================

#[test]
fn test_cwe_routing_enabled_with_language_override() {
    // Router enabled with language override - model should be applied when no CWE match
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "rust".to_string(),
        PromptSpec {
            prompt_template: "rust_specialized".to_string(),
            model_override: Some("rust-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // Create finding with .rs extension (rust language)
    let mut findings = vec![create_finding_with_cwe(
        Some("CWE-79".to_string()),
        "src/app.rs",
        Severity::High,
    )];

    simulate_cwe_routing(&mut findings, &router);

    // Finding should have the language-based model override applied
    assert_eq!(findings[0].llm_model, Some("rust-model".to_string()));

    // Verify language detection works correctly
    assert_eq!(utilities::detect_language("src/app.rs"), "rust");
}

// ============================================================================
// Test: Multiple findings with different CWEs
// ============================================================================

#[test]
fn test_cwe_routing_multiple_findings_different_cwes() {
    // Multiple findings with different CWEs - only matching ones get model overrides
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: Some("xss-model".to_string()),
        },
    );
    cwe_overrides.insert(
        "89".to_string(),
        PromptSpec {
            prompt_template: "sqli_specialized".to_string(),
            model_override: Some("sqli-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    let mut findings = vec![
        create_finding_with_cwe(Some("CWE-79".to_string()), "src/app.rs", Severity::High),
        create_finding_with_cwe(Some("CWE-89".to_string()), "src/db.rs", Severity::Critical),
        create_finding_with_cwe(
            Some("CWE-20".to_string()),
            "src/config.rs",
            Severity::Medium,
        ),
        create_finding_with_cwe(
            Some("CWE-79".to_string()),
            "src/frontend.js",
            Severity::High,
        ),
    ];

    simulate_cwe_routing(&mut findings, &router);

    // Verify each finding got the correct model or none
    assert_eq!(
        findings[0].llm_model,
        Some("xss-model".to_string()),
        "CWE-79 should get xss-model"
    );
    assert_eq!(
        findings[1].llm_model,
        Some("sqli-model".to_string()),
        "CWE-89 should get sqli-model"
    );
    assert!(
        findings[2].llm_model.is_none(),
        "CWE-20 should have no model override"
    );
    assert_eq!(
        findings[3].llm_model,
        Some("xss-model".to_string()),
        "CWE-79 should get xss-model"
    );
}

// ============================================================================
// Test: CWE priority over language
// ============================================================================

#[test]
fn test_cwe_routing_cwe_priority_over_language() {
    // CWE override should take priority over language override
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: Some("xss-model".to_string()),
        },
    );

    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "rust".to_string(),
        PromptSpec {
            prompt_template: "rust_specialized".to_string(),
            model_override: Some("rust-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // Rust file with CWE-79 - should get xss-model (CWE priority) not rust-model
    let mut findings = vec![create_finding_with_cwe(
        Some("CWE-79".to_string()),
        "src/app.rs",
        Severity::High,
    )];

    simulate_cwe_routing(&mut findings, &router);

    // CWE override should win
    assert_eq!(findings[0].llm_model, Some("xss-model".to_string()));
}

// ============================================================================
// Test: Different file extensions (language detection)
// ============================================================================

#[test]
fn test_cwe_routing_different_file_extensions() {
    // Test language detection with various file extensions
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "python".to_string(),
        PromptSpec {
            prompt_template: "python_specialized".to_string(),
            model_override: Some("python-model".to_string()),
        },
    );
    language_overrides.insert(
        "javascript".to_string(),
        PromptSpec {
            prompt_template: "js_specialized".to_string(),
            model_override: Some("js-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    let mut findings = vec![
        create_finding_with_cwe(Some("CWE-20".to_string()), "src/app.py", Severity::Medium),
        create_finding_with_cwe(Some("CWE-20".to_string()), "src/app.js", Severity::Medium),
        create_finding_with_cwe(Some("CWE-20".to_string()), "src/app.rs", Severity::Medium),
    ];

    simulate_cwe_routing(&mut findings, &router);

    // Python file should get python-model
    assert_eq!(findings[0].llm_model, Some("python-model".to_string()));
    // JavaScript file should get js-model
    assert_eq!(findings[1].llm_model, Some("js-model".to_string()));
    // Rust file has no language override, so no model
    assert!(findings[2].llm_model.is_none());
}

// ============================================================================
// Test: CWE ID format normalization
// ============================================================================

#[test]
fn test_cwe_routing_cwe_id_format_normalization() {
    // Test that different CWE ID formats all work correctly
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: Some("xss-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides,
        language_overrides: HashMap::new(),
    };

    let router = CweRouter::from_config(&config);

    // Create findings with different CWE ID formats
    let mut findings = vec![
        create_finding_with_cwe(Some("CWE-79".to_string()), "src/app1.rs", Severity::High),
        create_finding_with_cwe(Some("79".to_string()), "src/app2.rs", Severity::High),
        create_finding_with_cwe(Some("cwe-79".to_string()), "src/app3.rs", Severity::High),
    ];

    simulate_cwe_routing(&mut findings, &router);

    // All formats should match and get the model
    assert_eq!(findings[0].llm_model, Some("xss-model".to_string()));
    assert_eq!(findings[1].llm_model, Some("xss-model".to_string()));
    assert_eq!(findings[2].llm_model, Some("xss-model".to_string()));
}

// ============================================================================
// Test: Finding without CWE ID falls back to language routing
// ============================================================================

#[test]
fn test_cwe_routing_no_cwe_id_falls_back_to_language() {
    // Finding with no CWE ID should fall back to language-based routing
    let mut language_overrides = HashMap::new();
    language_overrides.insert(
        "rust".to_string(),
        PromptSpec {
            prompt_template: "rust_specialized".to_string(),
            model_override: Some("rust-model".to_string()),
        },
    );

    let config = RouterConfig {
        enabled: true,
        default_prompt: "llm_static_analysis".to_string(),
        cwe_overrides: HashMap::new(),
        language_overrides,
    };

    let router = CweRouter::from_config(&config);

    // Finding with no CWE ID
    let mut findings = vec![create_finding_with_cwe(
        None,
        "src/app.rs",
        Severity::Medium,
    )];

    simulate_cwe_routing(&mut findings, &router);

    // Should get language-based model
    assert_eq!(findings[0].llm_model, Some("rust-model".to_string()));
}
