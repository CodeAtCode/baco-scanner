//! Tests for rationale check step in LLM verification.
//!
//! This module tests the LLM-as-judge rationale validation feature from paper CORRECT (arxiv:2504.13474).
//! The feature evaluates the reasoning behind vulnerability findings to reduce false positives.

use baco::findings::{IssueCategory, SecurityIssue, Severity, VulnerabilityFinding};
use baco::llm_verification::{rationale_check_template, RationaleVerdict};

/// Create a test finding with rationale check specific fields.
fn make_rationale_finding(title: &str, description: &str, code: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        description: description.to_string(),
        severity: Severity::High,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some(code.to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this issue".to_string()),
        code_location: Some("src/test.rs:42".to_string()),
        already_reported: false,
        sources: vec!["llm_analysis".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: Some(SecurityIssue {
            category: IssueCategory::Injection,
            cwe_id: Some("CWE-79".to_string()),
            owasp_category: Some("XSS".to_string()),
            mitre_attack: None,
            custom_tags: vec!["xss".to_string()],
        }),
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
    }
}

#[test]
fn test_rationale_template_contains_finding_info() {
    let finding = make_rationale_finding(
        "XSS Vulnerability",
        "Cross-site scripting in user input handling",
        "document.getElementById('output').innerHTML = userInput;",
    );

    let template = rationale_check_template(&finding);

    // Template should contain finding description
    assert!(
        template.contains("Cross-site scripting"),
        "Template should contain finding description"
    );

    // Template should contain CWE ID
    assert!(
        template.contains("CWE-79"),
        "Template should contain CWE ID"
    );

    // Template should contain code snippet
    assert!(
        template.contains("innerHTML"),
        "Template should contain code snippet"
    );

    // Template should ask for JSON response
    assert!(
        template.contains("is_sound"),
        "Template should request is_sound field"
    );
    assert!(
        template.contains("confidence_adjustment"),
        "Template should request confidence_adjustment field"
    );
}

#[test]
fn test_rationale_template_format() {
    let finding = make_rationale_finding(
        "SQL Injection",
        "SQL injection in query",
        "query + userInput",
    );
    let template = rationale_check_template(&finding);

    // Should be non-empty
    assert!(!template.is_empty(), "Template should not be empty");

    // Should contain key sections
    assert!(
        template.contains("Evaluate the reasoning"),
        "Template should contain evaluation instruction"
    );
    assert!(
        template.contains("logical"),
        "Template should mention logical errors"
    );
}

#[test]
fn test_rationale_verdict_sound_boosts_confidence() {
    // Test that a sound rationale verdict has positive confidence adjustment
    let verdict = RationaleVerdict {
        is_sound: true,
        issues: vec![],
        confidence_adjustment: 0.10,
    };

    assert!(verdict.is_sound);
    assert!(verdict.confidence_adjustment > 0.0);
    assert!((verdict.confidence_adjustment - 0.10).abs() < 0.001);
    assert!(verdict.issues.is_empty());
}

#[test]
fn test_rationale_verdict_flawed_penalizes() {
    // Test that a flawed rationale verdict has negative confidence adjustment
    let verdict = RationaleVerdict {
        is_sound: false,
        issues: vec![
            "Reasoning assumes user input is sanitized".to_string(),
            "No validation of input length".to_string(),
        ],
        confidence_adjustment: -0.20,
    };

    assert!(!verdict.is_sound);
    assert!(verdict.confidence_adjustment < 0.0);
    assert!((verdict.confidence_adjustment - (-0.20)).abs() < 0.001);
    assert_eq!(verdict.issues.len(), 2);
}

#[test]
fn test_rationale_verdict_neutral_for_llm_failure() {
    // Test that LLM failure results in neutral adjustment
    let verdict = RationaleVerdict {
        is_sound: true, // Default to true on failure
        issues: vec![],
        confidence_adjustment: 0.0,
    };

    assert_eq!(verdict.confidence_adjustment, 0.0);
}

#[test]
fn test_rationale_verdict_serialization() {
    let verdict = RationaleVerdict {
        is_sound: true,
        issues: vec!["Issue 1".to_string(), "Issue 2".to_string()],
        confidence_adjustment: 0.10,
    };

    // Test JSON serialization
    let json = serde_json::to_string(&verdict).expect("Failed to serialize verdict");
    assert!(json.contains("is_sound"));
    assert!(json.contains("issues"));
    assert!(json.contains("confidence_adjustment"));

    // Test deserialization
    let parsed: RationaleVerdict =
        serde_json::from_str(&json).expect("Failed to deserialize verdict");
    assert_eq!(parsed.is_sound, verdict.is_sound);
    assert_eq!(parsed.issues, verdict.issues);
    assert!((parsed.confidence_adjustment - verdict.confidence_adjustment).abs() < 0.001);
}

#[test]
fn test_rationale_verdict_json_parsing_sound() {
    let json = r#"{
        "is_sound": true,
        "issues": [],
        "confidence_adjustment": 0.10
    }"#;

    let verdict: RationaleVerdict = serde_json::from_str(json).expect("Failed to parse JSON");

    assert!(verdict.is_sound);
    assert!(verdict.issues.is_empty());
    assert!((verdict.confidence_adjustment - 0.10).abs() < 0.001);
}

#[test]
fn test_rationale_verdict_json_parsing_flawed() {
    let json = r#"{
        "is_sound": false,
        "issues": ["Reasoning error 1", "Reasoning error 2"],
        "confidence_adjustment": -0.20
    }"#;

    let verdict: RationaleVerdict = serde_json::from_str(json).expect("Failed to parse JSON");

    assert!(!verdict.is_sound);
    assert_eq!(verdict.issues.len(), 2);
    assert!((verdict.confidence_adjustment - (-0.20)).abs() < 0.001);
}

#[test]
fn test_template_includes_file_path() {
    let finding = make_rationale_finding("Test", "Description", "code");
    let template = rationale_check_template(&finding);

    assert!(
        template.contains("src/test.rs"),
        "Template should include file path"
    );
}

#[test]
fn test_template_includes_line_number() {
    let finding = make_rationale_finding("Test", "Description", "code");
    let template = rationale_check_template(&finding);

    assert!(
        template.contains("42"),
        "Template should include line number"
    );
}
