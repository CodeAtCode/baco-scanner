//! PoC generation test helpers.
//!
//! This module consolidates duplicated PoC generation test code including:
//! - Template creation blocks (26-35 line repetitions)
//! - Finding creation helpers
//! - Category-based test utilities
//!
//! Reduces duplication from multiple 26-35 line blocks to shared helpers.

use baco::findings::VulnerabilityFinding;
use baco::findings::{IssueCategory, SecurityIssue, Severity, VerificationStatus};
use baco::poc_generation::{PoCFormat, PoCGenerationEngine, PoCTemplate};
use std::collections::HashMap;

/// Helper to create a test finding with specific CWE.
///
/// This consolidates the duplicated `create_test_finding` function found in
/// `tests/unit/poc_generation.rs`.
///
/// # Arguments
/// * `cwe_id` - CWE identifier
/// * `severity` - Severity level
///
/// # Returns
/// A `VulnerabilityFinding` with the specified CWE
pub fn create_test_finding(cwe_id: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-1".to_string(),
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability".to_string(),
        severity,
        confidence_score: 0.9,
        cwe_id: Some(cwe_id.to_string()),
        file_path: "test.py".to_string(),
        line_number: Some(42),
        code_snippet: Some("execute(user_input)".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
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

/// Helper to create a finding with security issue category (no CWE).
///
/// This consolidates the duplicated `create_test_finding_with_category` function.
///
/// # Arguments
/// * `category` - Issue category
/// * `severity` - Severity level
///
/// # Returns
/// A `VulnerabilityFinding` with the specified category
pub fn create_test_finding_with_category(
    category: IssueCategory,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-2".to_string(),
        title: "Security Issue Finding".to_string(),
        description: "Finding with security issue category".to_string(),
        severity,
        confidence_score: 0.9,
        cwe_id: None,
        file_path: "test.py".to_string(),
        line_number: Some(42),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: Some(SecurityIssue {
            category,
            cwe_id: None,
            owasp_category: None,
            mitre_attack: None,
            custom_tags: vec![],
        }),
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

/// Creates a PoC template for testing.
///
/// This consolidates the duplicated template creation blocks (26-35 lines) found in
/// `src/poc_generation.rs:369-377` and `src/poc_generation.rs:416-424`, as well as
/// test duplicates in `tests/unit/poc_generation.rs:598-607` and `610-619`.
///
/// # Arguments
/// * `cwe_id` - CWE identifier
/// * `format` - PoC format
/// * `description` - Template description
/// * `vulnerable_pattern` - The vulnerable code pattern
///
/// # Returns
/// A `PoCTemplate` with the specified parameters
pub fn create_poc_template(
    cwe_id: &str,
    format: PoCFormat,
    description: &str,
    vulnerable_pattern: &str,
) -> PoCTemplate {
    PoCTemplate::new(
        cwe_id.to_string(),
        format,
        vulnerable_pattern.to_string(),
        "safe_code".to_string(),
        description.to_string(),
    )
}

/// Creates a PoC template with mitigation pattern.
///
/// # Arguments
/// * `cwe_id` - CWE identifier
/// * `format` - PoC format
/// * `description` - Template description
/// * `vulnerable_pattern` - The vulnerable code pattern
/// * `mitigation_pattern` - The mitigation code pattern
///
/// # Returns
/// A `PoCTemplate` with both vulnerable and mitigation patterns
pub fn create_poc_template_with_mitigation(
    cwe_id: &str,
    format: PoCFormat,
    description: &str,
    vulnerable_pattern: &str,
    mitigation_pattern: &str,
) -> PoCTemplate {
    PoCTemplate::new(
        cwe_id.to_string(),
        format,
        vulnerable_pattern.to_string(),
        mitigation_pattern.to_string(),
        description.to_string(),
    )
}

/// Creates a PoC generation engine with pre-loaded templates for testing.
///
/// # Arguments
/// * `templates` - Map of template keys to templates
///
/// # Returns
/// A `PoCGenerationEngine` with the specified templates pre-loaded
pub fn create_poc_engine_with_templates(
    templates: HashMap<String, PoCTemplate>,
) -> PoCGenerationEngine {
    let mut engine = PoCGenerationEngine::new();
    for (key, template) in templates {
        engine.templates.insert(key, template);
    }
    engine
}

/// Creates a PoC generation engine with default injection templates.
///
/// # Returns
/// A `PoCGenerationEngine` with basic injection templates pre-loaded
pub fn create_default_injection_engine() -> PoCGenerationEngine {
    let mut engine = PoCGenerationEngine::new();

    // Add basic injection templates for testing
    let injection_templates = vec![
        (
            "CWE-89:Python",
            create_poc_template(
                "CWE-89",
                PoCFormat::Python,
                "SQL Injection example",
                "cursor.execute(query)",
            ),
        ),
        (
            "CWE-89:Rust",
            create_poc_template(
                "CWE-89",
                PoCFormat::Rust,
                "SQL Injection example in Rust",
                "query.execute(&sql)",
            ),
        ),
    ];

    for (key, template) in injection_templates {
        engine.templates.insert(key.to_string(), template);
    }

    engine
}
