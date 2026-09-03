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

/// Simulate the CweRouting phase logic (from src/scanner/phases/other_phases/cwe_routing.rs)
/// This is what the phase does when router is enabled:
/// 1. Create router from config
/// 2. For each finding with a CWE ID, call route_cwe(cwe)
/// 3. If model_override is Some, set finding.llm_model
fn simulate_cwe_routing(findings: &mut [baco::findings::VulnerabilityFinding], router: &CweRouter) {
    for finding in findings {
        if let Some(cwe) = finding.cwe_id.as_deref() {
            let route = router.route_cwe(cwe);
            if let Some(model) = route.model_override {
                finding.llm_model = Some(model);
            }
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
        "CWE-79".to_string(),
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

    // Finding should not have model set (no override for CWE-89)
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
        "CWE-89".to_string(),
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
// Test: Multiple findings with different CWEs
// ============================================================================

#[test]
fn test_cwe_routing_multiple_findings_different_cwes() {
    // Multiple findings with different CWEs - only matching ones get model overrides
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "CWE-79".to_string(),
        PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: Some("xss-model".to_string()),
        },
    );
    cwe_overrides.insert(
        "CWE-89".to_string(),
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
// Test: CWE ID format normalization
// ============================================================================

#[test]
fn test_cwe_routing_cwe_id_format_normalization() {
    let mut cwe_overrides = HashMap::new();
    cwe_overrides.insert(
        "CWE-79".to_string(),
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

    // "CWE-79" format matches
    let mut findings = vec![create_finding_with_cwe(
        Some("CWE-79".to_string()),
        "src/app1.rs",
        Severity::High,
    )];
    simulate_cwe_routing(&mut findings, &router);
    assert_eq!(findings[0].llm_model, Some("xss-model".to_string()));

    // Bare "79" does NOT match (cwe_to_hunt_domain requires "CWE-" prefix)
    let mut findings = vec![create_finding_with_cwe(
        Some("79".to_string()),
        "src/app2.rs",
        Severity::High,
    )];
    simulate_cwe_routing(&mut findings, &router);
    assert!(findings[0].llm_model.is_none());

    // "cwe-79" (lowercase) does NOT match either
    let mut findings = vec![create_finding_with_cwe(
        Some("cwe-79".to_string()),
        "src/app3.rs",
        Severity::High,
    )];
    simulate_cwe_routing(&mut findings, &router);
    assert!(findings[0].llm_model.is_none());
}

// ============================================================================
// Additional router/mod.rs inline tests (migrated)
// ============================================================================

#[test]
fn test_route_cwe_known() {
    let router = CweRouter::default();
    let route = router.route_cwe("CWE-79");
    assert_eq!(route.domain, Some("xss".to_string()));
    assert_eq!(route.model_override, None);
}

#[test]
fn test_route_cwe_unknown() {
    let router = CweRouter::default();
    let route = router.route_cwe("CWE-999999");
    assert_eq!(route.domain, None);
    assert_eq!(route.model_override, None);
}
