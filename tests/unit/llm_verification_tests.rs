//! Unit tests for LLM verification module
//!
//! Tests cover: render_template, VerificationResult, VerificationReport,
//! TriageVerdict, TriageResult, RationaleVerdict

use baco::findings::{
    IssueCategory, SecurityIssue, Severity, VerificationStatus, VulnerabilityFinding,
};
use baco::llm_verification::{
    render_template, RationaleVerdict, TriageResult, TriageVerdict, VerificationReport,
    VerificationResult,
};
use baco::project_type::ProjectType;
use std::collections::HashMap;

// ============================================================================
// render_template Tests
// ============================================================================

#[test]
fn test_render_template_percent_syntax() {
    let template = "Hello %%NAME%%, welcome to %%PLACE%%!";
    let mut variables = HashMap::new();
    variables.insert("NAME".to_string(), "Alice".to_string());
    variables.insert("PLACE".to_string(), "Rustland".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Hello Alice, welcome to Rustland!");
}

#[test]
fn test_render_template_brace_syntax() {
    let template = "Hello {{NAME}}, welcome to {{PLACE}}!";
    let mut variables = HashMap::new();
    variables.insert("NAME".to_string(), "Bob".to_string());
    variables.insert("PLACE".to_string(), "Codeville".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Hello Bob, welcome to Codeville!");
}

#[test]
fn test_render_template_mixed_syntax() {
    let template = "%%GREETING%%, {{NAME}}!";
    let mut variables = HashMap::new();
    variables.insert("GREETING".to_string(), "Good morning".to_string());
    variables.insert("NAME".to_string(), "Charlie".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Good morning, Charlie!");
}

#[test]
fn test_render_template_empty_variables() {
    let template = "Hello %%NAME%%!";
    let variables: HashMap<String, String> = HashMap::new();

    let result = render_template(template, &variables);

    assert_eq!(result, "Hello %%NAME%%!");
}

#[test]
fn test_render_template_missing_variable() {
    let template = "Hello %%NAME%%, age %%AGE%%!";
    let mut variables = HashMap::new();
    variables.insert("NAME".to_string(), "Dave".to_string());

    let result = render_template(template, &variables);

    assert_eq!(result, "Hello Dave, age %%AGE%%!");
}

// ============================================================================
// TriageVerdict Tests
// ============================================================================

#[test]
fn test_triage_verdict_display_true_positive() {
    let verdict = TriageVerdict::TruePositive;
    assert_eq!(verdict.to_string(), "true_positive");
}

#[test]
fn test_triage_verdict_display_false_positive() {
    let verdict = TriageVerdict::FalsePositive;
    assert_eq!(verdict.to_string(), "false_positive");
}

// ============================================================================
// TriageResult Tests
// ============================================================================

#[test]
fn test_triage_result_creation() {
    let result = TriageResult {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.85,
        reasoning: "Clear vulnerability pattern detected".to_string(),
    };

    assert_eq!(result.verdict, TriageVerdict::TruePositive);
    assert_eq!(result.confidence, 0.85);
    assert_eq!(result.reasoning, "Clear vulnerability pattern detected");
}

#[test]
fn test_triage_result_false_positive() {
    let result = TriageResult {
        verdict: TriageVerdict::FalsePositive,
        confidence: 0.92,
        reasoning: "Code is test code, not production".to_string(),
    };

    assert_eq!(result.verdict, TriageVerdict::FalsePositive);
    assert!(result.confidence > 0.9);
}

// ============================================================================
// RationaleVerdict Tests
// ============================================================================

#[test]
fn test_rationale_verdict_sound() {
    let verdict = RationaleVerdict {
        is_sound: true,
        issues: vec![],
        confidence_adjustment: 0.10,
    };

    assert!(verdict.is_sound);
    assert!(verdict.issues.is_empty());
    assert_eq!(verdict.confidence_adjustment, 0.10);
}

#[test]
fn test_rationale_verdict_flawed() {
    let verdict = RationaleVerdict {
        is_sound: false,
        issues: vec![
            "Unsupported assumption".to_string(),
            "Missing evidence".to_string(),
        ],
        confidence_adjustment: -0.20,
    };

    assert!(!verdict.is_sound);
    assert_eq!(verdict.issues.len(), 2);
    assert_eq!(verdict.confidence_adjustment, -0.20);
}

#[test]
fn test_rationale_verdict_neutral() {
    let verdict = RationaleVerdict {
        is_sound: true,
        issues: vec![],
        confidence_adjustment: 0.0,
    };

    assert!(verdict.is_sound);
    assert_eq!(verdict.confidence_adjustment, 0.0);
}

#[test]
fn test_rationale_verdict_partial_eq() {
    let v1 = RationaleVerdict {
        is_sound: true,
        issues: vec![],
        confidence_adjustment: 0.10,
    };
    let v2 = RationaleVerdict {
        is_sound: true,
        issues: vec![],
        confidence_adjustment: 0.10,
    };
    let v3 = RationaleVerdict {
        is_sound: false,
        issues: vec![],
        confidence_adjustment: 0.0,
    };

    assert_eq!(v1, v2);
    assert_ne!(v1, v3);
}

// ============================================================================
// VerificationResult Tests
// ============================================================================

#[test]
fn test_verification_result_creation() {
    let result = VerificationResult {
        finding_id: "test-123".to_string(),
        status: VerificationStatus::Confirmed,
        confidence: 0.85,
        notes: "Verified via manual review".to_string(),
        mitigating_factors: vec!["Input is sanitized".to_string()],
        related_patterns: vec!["CWE-79".to_string()],
        false_positive_reason: None,
    };

    assert_eq!(result.finding_id, "test-123");
    assert_eq!(result.status, VerificationStatus::Confirmed);
    assert_eq!(result.confidence, 0.85);
    assert_eq!(result.mitigating_factors.len(), 1);
}

#[test]
fn test_verification_result_false_positive() {
    let result = VerificationResult {
        finding_id: "test-456".to_string(),
        status: VerificationStatus::FalsePositive,
        confidence: 0.95,
        notes: "Test code, not production".to_string(),
        mitigating_factors: vec![],
        related_patterns: vec![],
        false_positive_reason: Some("Code is in test directory".to_string()),
    };

    assert_eq!(result.status, VerificationStatus::FalsePositive);
    assert!(result.false_positive_reason.is_some());
}

// ============================================================================
// VerificationReport Tests
// ============================================================================

#[test]
fn test_verification_report_creation() {
    let results: Vec<VerificationResult> = vec![];
    let report = VerificationReport {
        total_findings: 10,
        confirmed: 5,
        false_positives: 3,
        needs_review: 2,
        failed: 0,
        results,
        average_confidence: 0.78,
        high_confidence_findings: vec!["test-1".to_string(), "test-2".to_string()],
    };

    assert_eq!(report.total_findings, 10);
    assert_eq!(
        report.confirmed + report.false_positives + report.needs_review,
        10
    );
    assert_eq!(report.average_confidence, 0.78);
}

#[test]
fn test_verification_report_empty() {
    let results: Vec<VerificationResult> = vec![];
    let report = VerificationReport {
        total_findings: 0,
        confirmed: 0,
        false_positives: 0,
        needs_review: 0,
        failed: 0,
        results,
        average_confidence: 0.0,
        high_confidence_findings: vec![],
    };

    assert_eq!(report.total_findings, 0);
    assert!(report.results.is_empty());
}

// ============================================================================
// Integration Tests with VulnerabilityFinding
// ============================================================================

fn make_test_finding(title: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        description: format!("Test description for {}", title),
        severity,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("console.log(userInput);".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this issue".to_string()),
        code_location: Some("src/test.rs:42".to_string()),
        already_reported: false,
        sources: vec!["static_analysis".to_string()],
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
            owasp_category: Some("Injection".to_string()),
            mitre_attack: None,
            custom_tags: vec!["test".to_string()],
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

#[test]
fn test_verification_result_with_finding() {
    let finding = make_test_finding("XSS Vulnerability", Severity::High);

    let result = VerificationResult {
        finding_id: finding.id.clone(),
        status: VerificationStatus::Confirmed,
        confidence: 0.85,
        notes: format!("Verified: {} is vulnerable", finding.title),
        mitigating_factors: vec![],
        related_patterns: finding.cwe_id.clone().into_iter().collect(),
        false_positive_reason: None,
    };

    assert_eq!(result.finding_id, finding.id);
    assert_eq!(result.status, VerificationStatus::Confirmed);
}

#[test]
fn test_project_type_enum_variants() {
    // Verify all ProjectType variants exist and can be used
    let _web = ProjectType::Web;
    let _cli = ProjectType::CLI;
    let _library = ProjectType::Library;
    let _embedded = ProjectType::Embedded;
    let _firmware = ProjectType::Firmware;
    let _desktop = ProjectType::Desktop;
    let _game = ProjectType::Game;
    let _unknown = ProjectType::Unknown;
}

#[test]
fn test_verification_report_summary() {
    let results: Vec<VerificationResult> = vec![
        VerificationResult {
            finding_id: "1".to_string(),
            status: VerificationStatus::Confirmed,
            confidence: 0.9,
            notes: String::new(),
            mitigating_factors: vec![],
            related_patterns: vec![],
            false_positive_reason: None,
        },
        VerificationResult {
            finding_id: "2".to_string(),
            status: VerificationStatus::FalsePositive,
            confidence: 0.95,
            notes: String::new(),
            mitigating_factors: vec![],
            related_patterns: vec![],
            false_positive_reason: Some("Test code".to_string()),
        },
    ];

    let report = VerificationReport {
        total_findings: 2,
        confirmed: 1,
        false_positives: 1,
        needs_review: 0,
        failed: 0,
        results,
        average_confidence: 0.925,
        high_confidence_findings: vec!["1".to_string(), "2".to_string()],
    };

    assert_eq!(report.confirmed, 1);
    assert_eq!(report.false_positives, 1);
    assert_eq!(report.high_confidence_findings.len(), 2);
}
