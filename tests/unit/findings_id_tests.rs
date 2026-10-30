//! Unit tests for finding ID generation
//!
//! These tests verify that finding IDs are unique for distinct findings
//! and consistent for identical findings.

use baco::findings::VulnerabilityFinding;

#[test]
fn test_different_rule_ids_produce_different_ids() {
    // Two findings with same path, line, cwe_id but DIFFERENT rule_ids
    // should get DIFFERENT IDs
    let id1 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli-1",
        Some("query.execute(user_input)"),
    );

    let id2 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli-2", // Different rule_id
        Some("query.execute(user_input)"),
    );

    assert_ne!(
        id1, id2,
        "Findings with different rule_ids should have different IDs"
    );
}

#[test]
fn test_different_code_snippets_produce_different_ids() {
    // Two findings with same path, line, cwe_id, rule_id but DIFFERENT code_snippets
    // should get DIFFERENT IDs
    let id1 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    let id2 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some("db.query(raw_input)"), // Different code snippet
    );

    assert_ne!(
        id1, id2,
        "Findings with different code_snippets should have different IDs"
    );
}

#[test]
fn test_identical_findings_produce_same_id() {
    // Two findings with identical everything should get the SAME ID (idempotency)
    let id1 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    let id2 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    assert_eq!(
        id1, id2,
        "Identical findings should have the same ID (idempotency)"
    );
}

#[test]
fn test_different_lines_produce_different_ids() {
    // Two findings on different lines should get different IDs
    let id1 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    let id2 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(43), // Different line
        "CWE-89",
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    assert_ne!(
        id1, id2,
        "Findings on different lines should have different IDs"
    );
}

#[test]
fn test_different_files_produce_different_ids() {
    // Two findings in different files should get different IDs
    let id1 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    let id2 = VulnerabilityFinding::generate_id(
        "src/db.rs", // Different file
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    assert_ne!(
        id1, id2,
        "Findings in different files should have different IDs"
    );
}

#[test]
fn test_different_cwe_ids_produce_different_ids() {
    // Two findings with different CWE IDs should get different IDs
    let id1 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    let id2 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-79", // Different CWE
        "semgrep-rule-sqli",
        Some("query.execute(user_input)"),
    );

    assert_ne!(
        id1, id2,
        "Findings with different CWE IDs should have different IDs"
    );
}

#[test]
fn test_none_snippet_vs_empty_string() {
    // None snippet and empty string snippet should produce different IDs
    let id1 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        None, // No snippet
    );

    let id2 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule-sqli",
        Some(""), // Empty string snippet
    );

    assert_ne!(
        id1, id2,
        "None snippet and empty string snippet should produce different IDs"
    );
}

#[test]
fn test_title_fallback_when_rule_id_empty() {
    // When rule_id is empty, the title should still differentiate findings
    let id1 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "SQL Injection Detected", // Using title as rule_id
        Some("query.execute(user_input)"),
    );

    let id2 = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "XSS Vulnerability", // Different title
        Some("query.execute(user_input)"),
    );

    assert_ne!(
        id1, id2,
        "Findings with different titles (as rule_id fallback) should have different IDs"
    );
}

#[test]
fn test_id_format_is_hex_string() {
    // Verify that the ID is a valid hex string
    let id = VulnerabilityFinding::generate_id(
        "src/main.rs",
        Some(42),
        "CWE-89",
        "semgrep-rule",
        Some("code"),
    );

    // Should be a non-empty string
    assert!(!id.is_empty(), "ID should not be empty");

    // Should only contain hex characters
    assert!(
        id.chars().all(|c| c.is_ascii_hexdigit()),
        "ID should be a valid hex string, got: {}",
        id
    );

    // SHA256 produces 32 bytes = 64 hex characters
    assert_eq!(
        id.len(),
        64,
        "SHA256 hex ID should be 64 characters, got: {}",
        id.len()
    );
}
