//! Unit tests for discovery partitioning and CWE routing edge cases.
//!
//! Targets:
//! - src/scanner/phases/llm_phases/discovery.rs (partition_for_discovery)
//! - src/scanner/phases/other_phases/cwe_routing.rs (via CweRouter::route_cwe)
//! - src/scanner/phases/other_phases/synthesis.rs (phase runners - unreachable internals noted)

use baco::evidence::EvidenceSource;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::router::CweRouter;
use baco::scanner::phases::llm_phases::discovery::{
    build_stable_discovery_prefix, build_volatile_discovery_tail, partition_for_discovery,
};
use std::collections::HashMap;

// ============================================================================
// Test Fixtures
// ============================================================================

/// Create a minimal finding without any evidence
fn create_plain_finding(id: &str, file_path: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Test finding {}", id),
        description: format!("Description for {}", id),
        severity: Severity::Medium,
        confidence_score: 0.5,
        cwe_id: None,
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

/// Create a finding with LLM analysis evidence
fn create_llm_evidence_finding(id: &str, file_path: &str, phase: &str) -> VulnerabilityFinding {
    let mut f = create_plain_finding(id, file_path);
    f.add_evidence(
        EvidenceSource::LlmAnalysis(phase.to_string()),
        0.6,
        format!("Found by LLM {}", phase),
    );
    f
}

// ============================================================================
// Discovery Partition Tests - Edge Cases
// ============================================================================

/// Test partition with mixed evidence states
#[test]
fn test_partition_mixed_evidence_states() {
    let findings = vec![
        create_plain_finding("plain-1", "src/a.rs"),
        create_llm_evidence_finding("llm-1", "src/b.rs", "discovery"),
        create_plain_finding("plain-2", "src/c.rs"),
        create_llm_evidence_finding("llm-2", "src/d.rs", "static_analysis"),
        create_plain_finding("plain-3", "src/e.rs"),
    ];

    let (needs_discovery, already_described) = partition_for_discovery(findings);

    assert_eq!(needs_discovery.len(), 3, "Three findings need discovery");
    assert_eq!(already_described.len(), 2, "Two findings already described");

    // Verify plain findings are in needs_discovery
    let needs_ids: Vec<&str> = needs_discovery.iter().map(|f| f.id.as_str()).collect();
    assert!(needs_ids.contains(&"plain-1"));
    assert!(needs_ids.contains(&"plain-2"));
    assert!(needs_ids.contains(&"plain-3"));

    // Verify LLM evidence findings are in already_described
    let described_ids: Vec<&str> = already_described.iter().map(|f| f.id.as_str()).collect();
    assert!(described_ids.contains(&"llm-1"));
    assert!(described_ids.contains(&"llm-2"));
}

/// Test partition with empty input
#[test]
fn test_partition_empty_input() {
    let (needs_discovery, already_described) = partition_for_discovery(vec![]);

    assert!(needs_discovery.is_empty());
    assert!(already_described.is_empty());
}

/// Test partition where all findings have LLM evidence
#[test]
fn test_partition_all_have_llm_evidence() {
    let findings = vec![
        create_llm_evidence_finding("llm-1", "src/a.rs", "discovery"),
        create_llm_evidence_finding("llm-2", "src/b.rs", "static_analysis"),
    ];

    let (needs_discovery, already_described) = partition_for_discovery(findings);

    assert!(needs_discovery.is_empty());
    assert_eq!(already_described.len(), 2);
}

/// Test partition stability across repeated calls
#[test]
fn test_partition_stability_repeated_calls() {
    let findings = vec![
        create_plain_finding("plain-1", "src/a.rs"),
        create_llm_evidence_finding("llm-1", "src/b.rs", "discovery"),
        create_plain_finding("plain-2", "src/c.rs"),
    ];

    let (needs_1, described_1) = partition_for_discovery(findings.clone());
    let (needs_2, described_2) = partition_for_discovery(findings.clone());
    let (needs_3, described_3) = partition_for_discovery(findings);

    // Verify counts are stable
    assert_eq!(needs_1.len(), needs_2.len());
    assert_eq!(needs_2.len(), needs_3.len());
    assert_eq!(described_1.len(), described_2.len());
    assert_eq!(described_2.len(), described_3.len());

    // Verify IDs are consistent
    let needs_ids_1: Vec<&str> = needs_1.iter().map(|f| f.id.as_str()).collect();
    let needs_ids_2: Vec<&str> = needs_2.iter().map(|f| f.id.as_str()).collect();
    let needs_ids_3: Vec<&str> = needs_3.iter().map(|f| f.id.as_str()).collect();

    assert_eq!(needs_ids_1, needs_ids_2);
    assert_eq!(needs_ids_2, needs_ids_3);
}

/// Test discovery prompt construction includes file path and snippet
#[test]
fn test_discovery_prompt_includes_file_path_and_snippet() {
    let mut finding = create_plain_finding("test-1", "src/vulnerable.rs");
    finding.line_number = Some(42);
    finding.code_snippet = Some("vulnerable_code()".to_string());

    let tail = build_volatile_discovery_tail(&finding);

    assert!(
        tail.contains("src/vulnerable.rs"),
        "Prompt should include file path"
    );
    assert!(tail.contains("42"), "Prompt should include line number");
    assert!(
        tail.contains("Test finding test-1"),
        "Prompt should include title"
    );
}

/// Test stable discovery prefix with hunt prompts
#[test]
fn test_stable_discovery_prefix_with_hunt_prompts() {
    let mut hunt_prompts = HashMap::new();
    hunt_prompts.insert(
        "injection".to_string(),
        "Look for SQL injection patterns".to_string(),
    );
    hunt_prompts.insert(
        "xss".to_string(),
        "Look for XSS vulnerabilities".to_string(),
    );

    let findings = vec![create_plain_finding("test-1", "src/a.rs")];

    let prefix = build_stable_discovery_prefix(&findings, &hunt_prompts);

    assert!(
        prefix.contains("HUNT MODULE"),
        "Prefix should contain hunt module markers"
    );
    assert!(
        prefix.contains("injection"),
        "Prefix should include injection domain"
    );
    assert!(prefix.contains("xss"), "Prefix should include xss domain");
}

/// Test stable discovery prefix with empty hunt prompts
#[test]
fn test_stable_discovery_prefix_empty_hunt_prompts() {
    let findings = vec![create_plain_finding("test-1", "src/a.rs")];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix = build_stable_discovery_prefix(&findings, &hunt_prompts);

    assert!(prefix.contains("You are a security vulnerability analyzer"));
    assert!(!prefix.contains("HUNT MODULE"));
}

// ============================================================================
// CWE Routing Tests
// ============================================================================

/// Test route_cwe for known CWE numbers
#[test]
fn test_route_cwe_known_cwes() {
    let router = CweRouter::default();

    // Test various known CWEs from the registry
    let route_xss = router.route_cwe("CWE-79");
    assert_eq!(route_xss.domain, Some("xss".to_string()));

    let route_injection = router.route_cwe("CWE-89");
    assert_eq!(route_injection.domain, Some("injection".to_string()));

    let route_auth = router.route_cwe("CWE-287");
    assert_eq!(route_auth.domain, Some("auth".to_string()));

    let route_crypto = router.route_cwe("CWE-327");
    assert_eq!(route_crypto.domain, Some("crypto".to_string()));
}

/// Test route_cwe for unknown CWE fallback
#[test]
fn test_route_cwe_unknown_cwe_fallback() {
    let router = CweRouter::default();

    let route = router.route_cwe("CWE-999999");
    assert_eq!(route.domain, None);
    assert_eq!(route.model_override, None);
}

/// Test case-sensitive CWE ID matching (bare numbers don't match)
#[test]
fn test_cwe_id_case_sensitivity() {
    let router = CweRouter::default();

    // "CWE-79" matches
    let route_prefixed = router.route_cwe("CWE-79");
    assert_eq!(route_prefixed.domain, Some("xss".to_string()));

    // "79" (bare number) does NOT match
    let route_bare = router.route_cwe("79");
    assert_eq!(route_bare.domain, None);

    // "cwe-79" (lowercase) does NOT match
    let route_lower = router.route_cwe("cwe-79");
    assert_eq!(route_lower.domain, None);

    // "Cwe-79" (mixed case) does NOT match
    let route_mixed = router.route_cwe("Cwe-79");
    assert_eq!(route_mixed.domain, None);
}

/// Test empty findings list handling
#[test]
fn test_cwe_routing_empty_findings() {
    let router = CweRouter::default();
    let findings: Vec<VulnerabilityFinding> = vec![];

    // Should not panic on empty list
    for finding in &findings {
        if let Some(cwe) = finding.cwe_id.as_deref() {
            let _route = router.route_cwe(cwe);
        }
    }
    // Test passes if no panic
}

/// Test registry-driven routing for multiple CWE categories
#[test]
fn test_registry_driven_routing_three_categories() {
    let router = CweRouter::default();

    // XSS category
    let xss_route = router.route_cwe("CWE-79");
    assert_eq!(xss_route.domain, Some("xss".to_string()));

    // Injection category
    let injection_route = router.route_cwe("CWE-89");
    assert_eq!(injection_route.domain, Some("injection".to_string()));

    // Path traversal category
    let path_route = router.route_cwe("CWE-22");
    assert_eq!(path_route.domain, Some("path_traversal".to_string()));

    // Authentication category
    let auth_route = router.route_cwe("CWE-287");
    assert_eq!(auth_route.domain, Some("auth".to_string()));
}

/// Test CWE routing with model overrides via config
#[test]
fn test_cwe_routing_with_model_overrides() {
    use baco::config::{PromptSpec, RouterConfig};

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

    let xss_route = router.route_cwe("CWE-79");
    assert_eq!(xss_route.model_override, Some("xss-model".to_string()));

    let sqli_route = router.route_cwe("CWE-89");
    assert_eq!(sqli_route.model_override, Some("sqli-model".to_string()));

    // Unknown CWE should have no override
    let unknown_route = router.route_cwe("CWE-999");
    assert_eq!(unknown_route.model_override, None);
}

/// Test file extension case-insensitivity note
///
/// Note: The cwe_to_hunt_domain function is case-sensitive for CWE IDs.
/// File extension handling (e.g., .PHP vs .php) is typically done in
/// file discovery/indexing phases, not in CWE routing. This test documents
/// the current behavior.
#[test]
fn test_cwe_routing_documentation_extension_handling() {
    let router = CweRouter::default();

    // CWE routing uses case-sensitive CWE ID matching
    // File extension case handling is separate from CWE routing
    let route_upper = router.route_cwe("CWE-79");
    let route_lower = router.route_cwe("cwe-79");

    assert_eq!(route_upper.domain, Some("xss".to_string()));
    assert_eq!(route_lower.domain, None); // lowercase doesn't match
}

// ============================================================================
// Integration Tests - Combined Scenarios
// ============================================================================

/// Test full discovery partition flow with real finding data
#[test]
fn test_discovery_partition_realistic_scenario() {
    // Simulate findings from a real scan:
    // - Some from semgrep (no evidence)
    // - Some from prior LLM analysis (LlmAnalysis evidence)
    // - Some from CPG slice (CpgSlice evidence)

    let mut semgrep_finding = create_plain_finding("semgrep-1", "src/auth.rs");
    semgrep_finding.title = "SQL Injection".to_string();
    semgrep_finding.cwe_id = Some("CWE-89".to_string());

    let mut llm_finding =
        create_llm_evidence_finding("llm-static-1", "src/api.rs", "static_analysis");
    llm_finding.title = "XSS Vulnerability".to_string();
    llm_finding.cwe_id = Some("CWE-79".to_string());

    let mut cpg_finding = create_plain_finding("cpg-slice-1", "src/handler.rs");
    cpg_finding.title = "Command Injection".to_string();
    cpg_finding.cwe_id = Some("CWE-78".to_string());
    // CPG slice evidence is different from LLM evidence
    cpg_finding.add_evidence(
        EvidenceSource::CpgSlice("cpg_slice".to_string()),
        0.6,
        "CPG slice isolated vulnerable code".to_string(),
    );

    let findings = vec![semgrep_finding, llm_finding, cpg_finding];

    let (needs_discovery, already_described) = partition_for_discovery(findings);

    // Only the LLM-evidence finding should be in already_described
    assert_eq!(already_described.len(), 1);
    assert_eq!(already_described[0].id, "llm-static-1");

    // Semgrep and CPG findings need discovery
    assert_eq!(needs_discovery.len(), 2);
    let needs_ids: Vec<&str> = needs_discovery.iter().map(|f| f.id.as_str()).collect();
    assert!(needs_ids.contains(&"semgrep-1"));
    assert!(needs_ids.contains(&"cpg-slice-1"));
}

/// Test that partition correctly handles findings with multiple evidence sources
#[test]
fn test_partition_multiple_evidence_sources() {
    let mut finding = create_plain_finding("multi-evidence", "src/multi.rs");

    // Add multiple evidence sources including LLM
    finding.add_evidence(
        EvidenceSource::CpgSlice("cpg".to_string()),
        0.5,
        "CPG found issue".to_string(),
    );
    finding.add_evidence(
        EvidenceSource::LlmAnalysis("discovery".to_string()),
        0.6,
        "LLM discovered issue".to_string(),
    );
    finding.add_evidence(
        EvidenceSource::IndependentVerifier("manual".to_string()),
        0.9,
        "Manually verified".to_string(),
    );

    let (needs_discovery, already_described) = partition_for_discovery(vec![finding]);

    // Should be in already_described because it has LlmAnalysis evidence
    assert_eq!(needs_discovery.len(), 0);
    assert_eq!(already_described.len(), 1);
}
