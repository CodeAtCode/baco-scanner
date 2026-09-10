//! Tests for required security primitives in verification prompts.

use baco::config::ScannerConfig;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::preset;
use baco::scanner::phases::llm_phases::build_stable_verification_prefix;
use std::collections::HashMap;

/// Create a test finding with the given file path and CWE.
fn make_test_finding(file_path: &str, cwe_id: Option<&str>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-id".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity: Severity::High,
        confidence_score: 0.85,
        cwe_id: cwe_id.map(|s| s.to_string()),
        file_path: file_path.to_string(),
        line_number: Some(42),
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

#[test]
fn test_wp_preset_ships_required_primitives() {
    // Load wordpress-core preset and verify it ships required primitives
    let preset = preset::load_preset("wordpress-core").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let php_primitives = config.knowledge.required_security_primitives.get("php");
    assert!(
        php_primitives.is_some(),
        "wordpress-core preset should have 'php' in required_security_primitives"
    );
    let primitives = php_primitives.unwrap();
    assert!(
        primitives.contains(&"wp_verify_nonce".to_string()),
        "wordpress-core preset php primitives should contain 'wp_verify_nonce'"
    );
    assert!(
        primitives.contains(&"current_user_can".to_string()),
        "wordpress-core preset php primitives should contain 'current_user_can'"
    );

    // Also test wordpress-plugin preset
    let preset = preset::load_preset("wordpress-plugin").unwrap();
    let mut config = ScannerConfig::default();
    preset.merge_into(&mut config);

    let php_primitives = config.knowledge.required_security_primitives.get("php");
    assert!(
        php_primitives.is_some(),
        "wordpress-plugin preset should have 'php' in required_security_primitives"
    );
    let primitives = php_primitives.unwrap();
    assert!(
        primitives.contains(&"wp_verify_nonce".to_string()),
        "wordpress-plugin preset php primitives should contain 'wp_verify_nonce'"
    );
    assert!(
        primitives.contains(&"current_user_can".to_string()),
        "wordpress-plugin preset php primitives should contain 'current_user_can'"
    );
}

#[test]
fn test_prefix_includes_primitive_section_for_php() {
    // Build prefix with a PHP finding and primitives map
    let finding = make_test_finding("includes/ajax-handler.php", Some("CWE-352"));
    let findings = vec![finding];
    let primitives: HashMap<String, Vec<String>> = HashMap::from([(
        "php".to_string(),
        vec![
            "wp_verify_nonce".to_string(),
            "current_user_can".to_string(),
        ],
    )]);
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix = build_stable_verification_prefix(&findings, &hunt_prompts, &primitives);

    assert!(
        prefix.contains("Required Security Primitives"),
        "prefix should contain 'Required Security Primitives' section"
    );
    assert!(
        prefix.contains("wp_verify_nonce"),
        "prefix should contain 'wp_verify_nonce' primitive"
    );
    assert!(
        prefix.contains("language: php"),
        "prefix should specify 'language: php'"
    );
}

#[test]
fn test_prefix_omits_primitive_section_without_matching_language() {
    // Build prefix with a Rust finding (no php primitives should apply)
    let finding = make_test_finding("src/main.rs", Some("CWE-89"));
    let findings = vec![finding];
    let primitives: HashMap<String, Vec<String>> =
        HashMap::from([("php".to_string(), vec!["wp_verify_nonce".to_string()])]);
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix = build_stable_verification_prefix(&findings, &hunt_prompts, &primitives);

    assert!(
        !prefix.contains("Required Security Primitives"),
        "prefix should NOT contain 'Required Security Primitives' for non-matching language"
    );
}

#[test]
fn test_prefix_byte_stable_with_primitives() {
    // Two identical calls should return equal strings
    let finding = make_test_finding("includes/ajax-handler.php", Some("CWE-352"));
    let findings = vec![finding.clone()];
    let primitives: HashMap<String, Vec<String>> = HashMap::from([(
        "php".to_string(),
        vec![
            "wp_verify_nonce".to_string(),
            "current_user_can".to_string(),
        ],
    )]);
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix1 = build_stable_verification_prefix(&findings, &hunt_prompts, &primitives);
    let prefix2 = build_stable_verification_prefix(&findings, &hunt_prompts, &primitives);

    assert_eq!(
        prefix1, prefix2,
        "build_stable_verification_prefix should return byte-stable output"
    );
}

#[test]
fn test_php_alias_phtml_matches() {
    // .phtml extension should map to php
    let finding = make_test_finding("template.phtml", Some("CWE-352"));
    let findings = vec![finding];
    let primitives: HashMap<String, Vec<String>> =
        HashMap::from([("php".to_string(), vec!["wp_verify_nonce".to_string()])]);
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix = build_stable_verification_prefix(&findings, &hunt_prompts, &primitives);

    assert!(
        prefix.contains("Required Security Primitives"),
        "prefix should contain section for .phtml files (mapped to php)"
    );
    assert!(
        prefix.contains("language: php"),
        "prefix should show 'language: php' for .phtml files"
    );
}

#[test]
fn test_empty_map_omits_section() {
    // Empty primitives map should omit the section
    let finding = make_test_finding("includes/ajax-handler.php", Some("CWE-352"));
    let findings = vec![finding];
    let primitives: HashMap<String, Vec<String>> = HashMap::new();
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let prefix = build_stable_verification_prefix(&findings, &hunt_prompts, &primitives);

    assert!(
        !prefix.contains("Required Security Primitives"),
        "prefix should NOT contain section when primitives map is empty"
    );
}
