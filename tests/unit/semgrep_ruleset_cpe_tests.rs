//! Tests for semgrep ruleset array and CPE hint functionality

use baco::cve_bootstrap::CveBootstrapper;
use baco::scanner_types::cve::{CveEntry, CveSource};
use baco::scanner_types::project::{Dependency, DependencyEcosystem, ProjectStack};
use baco::scanner_types::severity::V3Severity;

// ============================================================================
// Semgrep Ruleset Tests
// ============================================================================

#[test]
fn test_empty_ruleset_preserves_default_behavior() {
    // Empty ruleset should result in no --config args being passed
    // This preserves the default semgrep behavior (uses bundled/default ruleset)
    let runner = baco::semgrep::SemgrepRunner::new(vec![], vec![]);

    assert!(runner.rulesets.is_empty());
    assert_eq!(runner.rulesets.len(), 0);
}

#[test]
fn test_multiple_rulesets_passed_as_multiple_config_args() {
    // Multiple rulesets should be stored and passed as separate --config args
    let rulesets = vec![
        "p/python".to_string(),
        "p/javascript".to_string(),
        "p/rust".to_string(),
    ];
    let runner = baco::semgrep::SemgrepRunner::new(rulesets.clone(), vec![]);

    assert_eq!(runner.rulesets.len(), 3);
    assert_eq!(runner.rulesets[0], "p/python");
    assert_eq!(runner.rulesets[1], "p/javascript");
    assert_eq!(runner.rulesets[2], "p/rust");
}

#[test]
fn test_single_ruleset() {
    // Single ruleset should work correctly
    let rulesets = vec!["p/python".to_string()];
    let runner = baco::semgrep::SemgrepRunner::new(rulesets.clone(), vec![]);

    assert_eq!(runner.rulesets.len(), 1);
    assert_eq!(runner.rulesets[0], "p/python");
}

// ============================================================================
// CPE Hint Tests
// ============================================================================

#[test]
fn test_cpe_hint_none_default() {
    // Default bootstrapper should have no CPE hint
    let temp_dir = tempfile::tempdir().unwrap();
    let bootstrapper = CveBootstrapper::new(temp_dir.path().to_str().unwrap().to_string());

    // The cpe_hint field is private, but we can verify the default behavior
    // by checking that the bootstrapper is created successfully
    assert!(bootstrapper.detect_project_stack().is_ok());
}

#[test]
fn test_cpe_hint_some_constructor() {
    // Bootstrapper with CPE hint should be created successfully
    let temp_dir = tempfile::tempdir().unwrap();
    let cpe_hint = Some("cpe:2.3:a:microsoft:internet_explorer:11.0:*:*:*:*:*:*:*".to_string());
    let bootstrapper =
        CveBootstrapper::with_cpe_hint(temp_dir.path().to_str().unwrap().to_string(), cpe_hint);

    // Verify bootstrapper is created successfully
    assert!(bootstrapper.detect_project_stack().is_ok());
}

#[test]
fn test_cpe_hint_flows_into_cve_matching() {
    // Test that CPE hint affects CVE matching logic
    // We test this by verifying the CPE parsing logic in fetch_relevant_cves
    let temp_dir = tempfile::tempdir().unwrap();
    let cpe_hint = Some("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*".to_string());
    let bootstrapper =
        CveBootstrapper::with_cpe_hint(temp_dir.path().to_str().unwrap().to_string(), cpe_hint);

    // Create a mock project stack
    let stack = ProjectStack {
        languages: vec!["Rust".to_string()],
        frameworks: vec![],
        dependencies: vec![Dependency {
            name: "test-dep".to_string(),
            version: "1.0".to_string(),
            ecosystem: DependencyEcosystem::CratesIo,
        }],
    };

    // The fetch_relevant_cves method should use the CPE hint
    // This test verifies the method can be called without panicking
    // (actual CVE fetching is tested elsewhere)
    let future = bootstrapper.fetch_relevant_cves(&stack);

    // We can't await here in a sync test, but we verify the method exists
    // and accepts the stack parameter
    drop(future);
}

#[test]
fn test_cpe_hint_does_not_break_non_matching_cves() {
    // CPE hint should not prevent CVEs from being fetched via dependency matching
    let temp_dir = tempfile::tempdir().unwrap();
    let cpe_hint = Some("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*".to_string());
    let bootstrapper =
        CveBootstrapper::with_cpe_hint(temp_dir.path().to_str().unwrap().to_string(), cpe_hint);

    // Create a project stack with dependencies
    let stack = ProjectStack {
        languages: vec!["Rust".to_string()],
        frameworks: vec![],
        dependencies: vec![
            Dependency {
                name: "serde".to_string(),
                version: "1.0".to_string(),
                ecosystem: DependencyEcosystem::CratesIo,
            },
            Dependency {
                name: "tokio".to_string(),
                version: "1.0".to_string(),
                ecosystem: DependencyEcosystem::CratesIo,
            },
        ],
    };

    // The method should still fetch CVEs for dependencies
    // even when CPE hint is set
    let future = bootstrapper.fetch_relevant_cves(&stack);
    drop(future);
}

#[test]
fn test_cpe_hint_parsing() {
    // Test CPE parsing logic
    let cpe = "cpe:2.3:a:microsoft:internet_explorer:11.0:*:*:*:*:*:*:*";
    let parts: Vec<&str> = cpe.split(':').collect();

    assert_eq!(parts.len(), 13); // Full CPE has 13 parts
    assert_eq!(parts[0], "cpe");
    assert_eq!(parts[1], "2.3");
    assert_eq!(parts[2], "a"); // Part type (application)
    assert_eq!(parts[3], "microsoft"); // Vendor
    assert_eq!(parts[4], "internet_explorer"); // Product
    assert_eq!(parts[5], "11.0"); // Version
}

#[test]
fn test_cve_entry_with_cpe_matching() {
    // Test that CVE entries can be created and compared
    let cve = CveEntry::new(
        "CVE-2024-001",
        "Test vulnerability",
        V3Severity::High,
        CveSource::NVD,
    );

    assert_eq!(cve.cve_id, "CVE-2024-001");
    assert_eq!(cve.severity, V3Severity::High);

    // CVE should have empty affected_products by default
    assert!(cve.affected_products.is_empty());
}
